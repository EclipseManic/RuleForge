# RuleForge Advanced Rule Corpus

This document is a detection-engineering compatibility corpus for RuleForge. The examples are original representative fixtures based on public vendor documentation. They are intentionally designed to exercise parsing, modeling, fidelity reporting, and native rendering. They are not production rules and must be validated against the target environment.

## How To Use This Corpus

For every fixture, RuleForge should:

1. Detect the source dialect.
2. Preserve the complete original source.
3. Extract the structured detection model.
4. Identify unsupported or vendor-specific constructs.
5. Never label a lossy translation as equivalent.
6. Preserve the source exactly when no native equivalent compiler exists.

Expected fidelity values:

- `exact`: the source can be preserved or safely regenerated.
- `safe_normalized`: syntax changes but the supported semantics remain equivalent.
- `partial`: some structure is modeled, but manual review is required.
- `unsupported`: the rule is preserved as source, but cannot be safely normalized.

## SIEM Rule Engineering Reference

This section teaches an analyst how to reason about each supported rule language. The examples use generic fields because real field names depend on the deployed parser, connector, data model, decoder, or custom schema.

### The three layers of a detection

1. **Intent:** what behavior is suspicious?
2. **Correlation model:** which events, keys, windows, counts, joins, exclusions, and enrichments create the detection?
3. **Vendor syntax:** how does the target SIEM express that model?

A flat `field/operator/value` row represents only one predicate. It must never replace the complete model for an advanced rule.

## Sigma Learning Reference

Sigma is a vendor-neutral YAML representation. It describes intent and detection structure; a backend converts it into a target query.

```yaml
title: Suspicious PowerShell With Administrative Context
id: 8c3c58c8-3f2e-4a42-9a9d-0c8bfa4ab123
status: test
author: Detection Engineering
description: Detects encoded PowerShell outside an approved account context.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - "\\powershell.exe"
      - "\\pwsh.exe"
    CommandLine|contains:
      - "-enc"
      - "-encodedcommand"
  filter:
    User:
      - "trusted-admin"
      - "automation-account"
  condition: selection and not filter
falsepositives:
  - Approved automation
level: high
```

Important Sigma variables and sections:

- `logsource` identifies telemetry category, product, and service.
- A named selection contains detection predicates.
- A YAML dictionary means `AND` between fields.
- A YAML list means `OR` between values.
- `condition` combines named selections.
- Modifiers such as `contains`, `startswith`, `endswith`, `re`, and `base64` change value semantics.
- `filter` is normally combined with `not`.
- `falsepositives` documents tuning context and is not automatically a query exclusion.
- `level`, tags, references, status, and author are metadata, not event predicates.
- Correlation rules, pipelines, and backends add multi-event and target-specific behavior.

## Splunk SPL / Enterprise Security Learning Reference

SPL is a pipeline language. Each pipe sends the current event table to another command, so command order matters.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| search process_name IN ("powershell.exe", "cmd.exe")
| lookup privileged_accounts user OUTPUT is_privileged
| where is_privileged="true"
| stats count AS process_count dc(dest_ip) AS destination_count values(command_line) AS commands by host user
| where process_count >= 3 AND destination_count >= 2
| eval risk_score=case(destination_count >= 5, 90, process_count >= 10, 80, true(), 60)
```

Important SPL constructs:

- `index` and `sourcetype` select and classify telemetry.
- `search` filters with search syntax; `where` evaluates expressions.
- `eval` creates calculated fields.
- `stats`, `eventstats`, and `streamstats` aggregate events.
- `transaction` groups ordered events with `startswith`, `endswith`, `maxspan`, and `maxpause`.
- `lookup` and `inputlookup` enrich from external tables.
- `join`, `rex`, `dedup`, and `timechart` change the event pipeline.
- `count`, `dc`, `values`, `latest`, `earliest`, `sum`, `avg`, `min`, and `max` are aggregation variables.
- `case`, `if`, `coalesce`, `isnull`, and `isnotnull` are expression functions.
- `IN`, wildcards, and `regex` have different matching semantics.

Architecture warning: replacing `stats dc(dest_ip)` with `stats count` changes the detection. Reordering a `lookup` before filtering can also change behavior.

## Microsoft Sentinel KQL Learning Reference

KQL operates on tables and produces tabular results. A Sentinel analytic rule also has scheduling, lookback, thresholds, entity mapping, alert grouping, and custom details outside the query.

```kusto
let suspicious = DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project DeviceId, AccountName, ProcessTime=Timestamp;
let network = DeviceNetworkEvents
| where RemotePort == 443
| project DeviceId, RemoteIP, NetworkTime=Timestamp;
suspicious
| join kind=inner network on DeviceId
| where NetworkTime between (ProcessTime .. ProcessTime + 10m)
| summarize FirstSeen=min(ProcessTime), LastSeen=max(NetworkTime), RemoteIPs=make_set(RemoteIP) by DeviceId, AccountName
```

Important KQL constructs:

- `let name = expression` creates named event streams.
- `where` filters rows.
- `project` selects or renames columns.
- `extend` creates calculated columns.
- `summarize` aggregates rows.
- `join`, `union`, `lookup`, and `leftanti` combine or exclude data.
- `count`, `dcount`, `make_set`, `arg_min`, and `arg_max` affect output semantics.
- `ago`, `between`, `in`, `has`, `has_any`, `contains`, `startswith`, and `matches regex` are different operators.
- `TimeGenerated` is important to scheduled-rule lookback behavior.
- Entity mapping, custom details, alert grouping, suppression, and incident settings are rule configuration outside KQL.

## Elastic EQL / Security Learning Reference

EQL is event-oriented. It has event categories and ordered sequence semantics that cannot safely be flattened into one boolean expression.

```eql
sequence by host.name with maxspan=10m
  [process where process.name in ("winword.exe", "excel.exe")]
  [network where destination.port == 443 and network.protocol == "https"]
  [process where process.name in ("powershell.exe", "cmd.exe") and process.command_line like ("*-enc*", "*-encodedcommand*")]
```

Important EQL constructs:

- Event categories include `process`, `network`, `file`, and `authentication`.
- `where` filters an event category.
- `sequence` requires stages in order.
- `by` correlates stages using keys.
- `maxspan` limits total sequence duration.
- `until` and negated stages express termination or absence.
- `in`, wildcard `:`, and `regex~` have different matching semantics.
- EQL sequences differ from Elastic threshold rules, which use separate count and grouping configuration.
- Index patterns, intervals, suppression, exceptions, risk scores, and response actions are rule metadata outside the EQL query.

## IBM QRadar AQL Learning Reference

AQL is SQL-like but includes QRadar Ariel functions and QRadar-specific time syntax.

```sql
SELECT sourceip,
       COUNT(*) AS event_count,
       SUM(magnitude) AS total_magnitude
FROM events
WHERE eventname ILIKE '%login%'
  AND sourceip IS NOT NULL
GROUP BY sourceip
HAVING COUNT(*) >= 10
LAST 15 MINUTES
```

Important AQL constructs:

- `events` and `flows` are different sources.
- `SELECT` defines output fields and aggregates.
- `WHERE` filters raw events or flows.
- `GROUP BY` defines aggregation keys.
- `HAVING` filters aggregate results.
- `LAST n MINUTES/HOURS/DAYS` defines the time range.
- `ILIKE`, `LIKE`, `MATCHES`, `IN`, `IS NULL`, and `IS NOT NULL` have different semantics.
- `LOGSOURCENAME`, `CATEGORYNAME`, and `RULENAME` are QRadar functions.
- X-Force functions and reference sets add external context.
- Saved searches, offense contribution, rule responses, and historical correlation are configured outside AQL.

## Google SecOps YARA-L 2.0 Learning Reference

YARA-L has a strict multi-section model. Each section has different meaning and must be parsed independently.

```yaral
rule brute_force_then_success {
  meta:
    author = "Detection Engineering"
    severity = "HIGH"

  events:
    $failed.metadata.event_type = "USER_LOGIN"
    $failed.security_result.action = "FAIL"
    $failed.target.user.userid = $user
    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.target.user.userid = $user
    $failed.metadata.event_timestamp.seconds < $success.metadata.event_timestamp.seconds

  match:
    $user over 10m

  outcome:
    $failed_count = count($failed.metadata.id)
    $risk_score = 90

  condition:
    #failed >= 5 and $success
}
```

Important YARA-L variables and constructs:

- `$e`, `$process`, `$network`, `$failed`, and `$success` are event variables.
- `$user`, `$host`, `$hash`, and similar names are placeholders.
- Equality between placeholders creates joins.
- `events` defines predicates and event-variable relationships.
- `match` defines grouping and time windows.
- `condition` decides whether an event group becomes a detection.
- `#event` counts event occurrences.
- `outcome` calculates risk, context, and analyst-facing values.
- `re.regex`, CIDR functions, array functions, and timestamp functions add specialized logic.
- Entity Graph and global-context joins are enrichment, not ordinary event fields.
- Composite detections consume earlier detections as input.

## CrowdStrike Falcon LogScale CQL Learning Reference

CQL is a pipeline language over normalized event fields. Pipeline order and transformations are part of the detection semantics.

```cql
#repo=windows
ImageFileName=/powershell\.exe/i
| CommandLine=/-(enc|encodedcommand)/i
| lookup(["privileged_accounts.csv"], field=UserName, key=UserName)
| groupBy([ComputerName, UserName], function=[count(as=event_count), count(field=RemoteAddressIP4, distinct=true, as=destinations)])
| event_count >= 5
```

Important CQL constructs:

- `#repo` selects a repository.
- Field and regex predicates filter events.
- Pipeline stages run left to right.
- `groupBy` creates grouped aggregates.
- `count`, distinct count, and aliases affect output semantics.
- `lookup` adds external table data.
- `case` creates branches.
- `parseJson` and parser functions transform raw data.
- Negated predicates create exclusions.
- Packages may contain parsers, alerts, dashboards, and lookup files outside the query.

## Wazuh Ruleset XML Learning Reference

Wazuh rules are structured XML and should always be parsed with an XML parser.

```xml
<rule id="100210" level="12" frequency="5" timeframe="300">
  <if_matched_sid>5710</if_matched_sid>
  <same_srcip />
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-enc</field>
  <description>Repeated encoded PowerShell activity.</description>
  <mitre><id>T1059.001</id></mitre>
  <group>process,execution,</group>
</rule>
```

Important Wazuh elements:

- `id` identifies the rule.
- `level` controls alert severity.
- `frequency` and `timeframe` create repeated-event correlation.
- `if_sid`, `if_matched_sid`, `if_group`, and `if_matched_group` create chains.
- `same_srcip`, `same_dstip`, `same_user`, and `same_field` define grouping.
- `field`, `match`, `regex`, `program_name`, and decoder-specific tags match data.
- `negate="yes"` expresses exclusions.
- `description`, `group`, and `mitre` provide analyst context.
- Decoder output determines whether a field is actually available.
- `wazuh-logtest` is required to verify decoder and rule behavior.

## Teaching Workflow For RuleForge Analysts

For every rule, an analyst should ask:

1. What event or behavior is the rule detecting?
2. Which fields are actual event predicates?
3. Which values are lists, regexes, or wildcards?
4. Are there exclusions or allowlists?
5. Is the rule single-event or multi-event?
6. What joins connect events?
7. What entity key groups the events?
8. What is the time window and schedule?
9. What aggregation or threshold triggers the rule?
10. Is there lookup, threat intelligence, or enrichment?
11. What output fields, risk score, severity, and metadata are produced?
12. Which parts are native syntax and which are portable intent?

The RuleForge UI and intermediate model should expose these questions through sections 1–3. A pasted rule is an import source; the structured model is the analyst workspace; the native renderer is the target-specific compiler.
## Sigma: Vendor-Neutral Detection Layer

Sigma separates metadata, logsource, detection selections, condition expressions, false positives, and severity. It is the canonical intermediate representation for simple cross-SIEM detections.

### Compound selection, filter, list values, and metadata

```yaml
title: Suspicious PowerShell With Administrative Context
id: 8c3c58c8-3f2e-4a42-9a9d-0c8bfa4ab123
status: test
author: Detection Engineering
description: Detects encoded PowerShell execution outside an approved administrative context.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - "\\powershell.exe"
      - "\\pwsh.exe"
    CommandLine|contains:
      - "-enc"
      - "-encodedcommand"
  filter:
    User:
      - "trusted-admin"
      - "automation-account"
  condition: selection and not filter
falsepositives:
  - Approved automation
level: high
```

### Correlation and aggregation fixture

```yaml
title: Repeated Failed Logins Followed By Success
status: experimental
logsource:
  product: windows
  service: security
detection:
  failed:
    EventID: 4625
  success:
    EventID: 4624
  condition: failed and success
level: high
```

Expected model coverage: metadata, logsource, named selections, list-valued fields, filters, boolean condition, false positives, and the fact that this fixture needs an explicit correlation model to express ordering and counts.

References:

- https://sigmahq.io/docs/basics/rules.html
- https://github.com/SigmaHQ/pySigma

## Splunk SPL / Enterprise Security

Splunk correlation searches can be pipeline programs. The parser must preserve search clauses, lookups, aggregation functions, aliases, joins, and adaptive-response metadata separately.

### Lookup, distinct aggregation, multiple thresholds, and grouping

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| search process_name IN ("powershell.exe", "cmd.exe")
| lookup privileged_accounts user OUTPUT is_privileged
| where is_privileged="true"
| stats count AS process_count dc(dest_ip) AS destination_count values(command_line) AS commands by host user
| where process_count >= 3 AND destination_count >= 2
| eval risk_score=case(destination_count >= 5, 90, process_count >= 10, 80, true(), 60)
```

### Transaction and ordered behavior

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4625 OR EventCode=4624)
| transaction user maxspan=10m startswith=(EventCode=4625) endswith=(EventCode=4624)
| where eventcount >= 5
| stats earliest(_time) AS first_seen latest(_time) AS last_seen values(src_ip) AS source_ips by user
```

Expected model coverage: index, sourcetype, field-value lists, lookup name and arguments, `stats` functions, distinct counts, aliases, `where` thresholds, `eval` risk scoring, transaction order, and maxspan.

References:

- https://docs.splunk.com/Documentation/ES/latest/Search/CorrelationSearches
- https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats
- https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Transaction

## Microsoft Sentinel KQL

Sentinel scheduled rules are built from KQL and include query logic, tables, joins, lookback, thresholds, entity mapping, custom details, alert grouping, and suppression. The query must preserve `TimeGenerated` semantics.

### Multi-table join with time relationship and aggregation

```kusto
let suspicious = DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project DeviceId, AccountName, ProcessTime=Timestamp;
let network = DeviceNetworkEvents
| where RemotePort == 443
| project DeviceId, RemoteIP, NetworkTime=Timestamp;
suspicious
| join kind=inner network on DeviceId
| where NetworkTime between (ProcessTime .. ProcessTime + 10m)
| summarize
    FirstSeen=min(ProcessTime),
    LastSeen=max(NetworkTime),
    RemoteIPs=make_set(RemoteIP)
    by DeviceId, AccountName
| extend EntityHost=DeviceId, EntityAccount=AccountName
```

### Sequence-like KQL with anti-join and exception logic

```kusto
let admin = _GetWatchlist('approved_admins') | project Account;
let failed = SigninLogs
| where ResultType != 0
| summarize FailedCount=count(), FirstFailure=min(TimeGenerated) by UserPrincipalName, IPAddress;
let success = SigninLogs
| where ResultType == 0
| project UserPrincipalName, IPAddress, SuccessTime=TimeGenerated;
failed
| join kind=inner success on UserPrincipalName, IPAddress
| where SuccessTime between (FirstFailure .. FirstFailure + 15m)
| join kind=leftanti admin on $left.UserPrincipalName == $right.Account
| where FailedCount >= 10
```

Expected model coverage: named streams, source tables, `where`, `has_any`, projections, inner joins, anti-joins, composite keys, temporal relationships, aggregations, `make_set`, watchlist enrichment, and entity outputs.

References:

- https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules
- https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/join-operator
- https://learn.microsoft.com/en-us/azure/sentinel/watchlists

## Elastic EQL / Elastic Security

Elastic EQL represents event categories and ordered sequences. A detection model must retain stage order, join keys, `maxspan`, negation, and event categories instead of flattening stages into one `AND` expression.

### Ordered sequence with shared host and maxspan

```eql
sequence by host.name with maxspan=10m
  [process where
    process.name in ("winword.exe", "excel.exe")]
  [network where
    destination.port == 443 and network.protocol == "https"]
  [process where
    process.name in ("powershell.exe", "cmd.exe") and
    process.command_line like ("*-enc*", "*-encodedcommand*")]
```

### Sequence with negation and terminating event

```eql
sequence by user.name with maxspan=30m
  [authentication where event.outcome == "failure"] by source.ip
  [authentication where event.outcome == "success"] by source.ip
  ![authentication where event.action == "logout"]
```

### Threshold-style aggregation note

```text
Event category: process
Condition: process.name == "rundll32.exe"
Threshold: at least 5 events
Window: 15 minutes
Group by: host.name
```

Expected model coverage: event categories, ordered stages, `by` keys, maxspan, negated stages, multiple joins, wildcard/list values, and the distinction between EQL sequence rules and Elastic threshold rules.

References:

- https://www.elastic.co/guide/en/security/current/eql.html
- https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html

## IBM QRadar AQL

QRadar AQL combines SQL-like projection and aggregation with QRadar-specific functions and time windows. The model must preserve selected expressions, aliases, functions, `WHERE`, `GROUP BY`, `HAVING`, `LAST`, and threat-intelligence calls.

### Aggregation, function call, grouping, and time window

```sql
SELECT sourceip,
       SUM(magnitude) AS total_magnitude,
       COUNT(*) AS event_count,
       CATEGORYNAME(category) AS category_name
FROM events
WHERE eventname ILIKE '%authentication%'
  AND XFORCE_IP_CONFIDENCE('Spam', sourceip) > 3
GROUP BY sourceip
HAVING SUM(magnitude) > 10 AND COUNT(*) >= 5
LAST 15 MINUTES
```

### Flow and event correlation search

```sql
SELECT sourceip, destinationip, SUM(bytes) AS total_bytes
FROM flows
WHERE destinationport IN (443, 8443)
  AND sourceip IS NOT NULL
GROUP BY sourceip, destinationip
HAVING SUM(bytes) > 100000000
LAST 1 HOURS
```

Expected model coverage: SELECT expressions, aliases, event/flow source, function calls, `IN`, null checks, aggregation metrics, multiple HAVING thresholds, group keys, and LAST duration.

References:

- https://www.ibm.com/docs/en/qradar-on-cloud?topic=searches-advanced-search-options
- https://www.ibm.com/docs/en/qradar-on-cloud?topic=options-aql-search-string-examples

## Google SecOps YARA-L 2.0

YARA-L is structurally richer than a flat query. The model must preserve `meta`, event variables, placeholders, relationships, `match`, `outcome`, `condition`, context graph joins, and composite detections.

### Multi-event correlation with outcome scoring

```yaral
rule brute_force_then_success {
  meta:
    author = "Detection Engineering"
    description = "Multiple failed logins followed by a successful login."
    severity = "HIGH"

  events:
    $failed.metadata.event_type = "USER_LOGIN"
    $failed.security_result.action = "FAIL"
    $failed.target.user.userid = $user
    $failed.principal.hostname = $hostname

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.target.user.userid = $user
    $success.principal.hostname = $hostname
    $failed.metadata.event_timestamp.seconds < $success.metadata.event_timestamp.seconds

  match:
    $user, $hostname over 10m

  outcome:
    $failed_count = count($failed.metadata.id)
    $risk_score = 90

  condition:
    #failed >= 5 and $success
}
```

### Context-aware IOC enrichment

```yaral
rule process_hash_threat_feed_match {
  meta:
    author = "Detection Engineering"
    severity = "CRITICAL"

  events:
    $process.metadata.event_type = "PROCESS_LAUNCH"
    $process.principal.hostname = $hostname
    $hash = $process.target.process.file.sha256

    $ioc.graph.metadata.entity_type = "FILE"
    $ioc.graph.metadata.product_name = "GCTI Feed"
    $ioc.graph.entity.file.sha256 = $hash

  match:
    $hostname over 15m

  outcome:
    $risk_score = 95
    $feed = array_distinct($ioc.graph.metadata.feed)

  condition:
    $process and $ioc
}
```

Expected model coverage: event variables, placeholder joins, ordering, match variables, windowing, counts, outcomes, threat-intelligence graph joins, and condition expressions.

References:

- https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples
- https://docs.cloud.google.com/chronicle/docs/detection/composite-detections

## CrowdStrike Falcon LogScale CQL

CQL is a pipeline language. The model must preserve repository scope, parser assumptions, pipeline stages, grouping, aggregations, lookups, and event transformations.

### Grouping, aggregation, and lookup enrichment

```cql
#repo=windows
ImageFileName=/powershell\.exe/i
CommandLine=/-(enc|encodedcommand)/i
| lookup(["privileged_accounts.csv"], field=UserName, key=UserName, include=[is_privileged])
| is_privileged=true
| groupBy([ComputerName, UserName], function=[count(as=process_count), count(field=RemoteAddressIP4, distinct=true, as=destination_count)])
| process_count >= 5
| destination_count >= 2
```

### Pipeline transformation and exclusion

```cql
#repo=network
| parseJson(field=@rawstring)
| case {
    eventType="dns" | Domain=/\.onion$/i | _case="tor_dns";
    eventType="http" | Url=/pastebin\.com/i | _case="suspicious_web";
  }
| !UserName="scanner-account"
| groupBy([ComputerName, UserName], function=count())
```

Expected model coverage: repository scope, regex predicates, lookup files, case branches, exclusions, JSON parsing, distinct aggregation, aliases, and pipeline order.

References:

- https://github.com/CrowdStrike/logscale-community-content
- https://library.humio.com/

## Wazuh Ruleset XML

Wazuh rules are XML documents with rule metadata, decoder fields, parent relationships, frequency correlation, same-field correlation, groups, and MITRE mappings. XML parsing is required; regex-only parsing is unsafe.

### Chained frequency correlation

```xml
<group name="authentication,custom,">
  <rule id="100210" level="12" frequency="5" timeframe="300">
    <if_matched_sid>5710</if_matched_sid>
    <same_srcip />
    <description>Multiple SSH authentication failures from one source.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,brute_force,</group>
  </rule>
</group>
```

### Decoder field rule with exclusion

```xml
<group name="process,windows,">
  <rule id="100220" level="10">
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
    <field name="win.eventdata.commandLine" negate="yes" type="pcre2">(?i)trusted-admin-script</field>
    <description>PowerShell execution outside the approved administrative script path.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

Expected model coverage: XML structure, IDs, levels, parent rule IDs, frequency, timeframe, same-field tags, field regex, negation, groups, descriptions, and MITRE IDs.

References:

- https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
- https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html

## Compatibility Expectations

A parser or renderer should not claim full support merely because it extracted one field. For every fixture, RuleForge should report:

- Which sections were parsed.
- Which event stages were preserved.
- Which joins and keys were preserved.
- Which aggregations and thresholds were preserved.
- Which lookups or enrichment operations were preserved.
- Whether the output is exact, safe-normalized, partial, or unsupported.

A complex rule with unsupported native features must remain available as an exact source artifact. The normalized editor must not silently replace it.

## Major Rule-Family Coverage Matrix

There is no finite list of "all SIEM rules": vendors allow arbitrary expressions, custom functions, schemas, plugins, and data sources. This matrix defines the major detection-engineering families that the RuleForge corpus must cover for every dialect.

Each row is a required fixture family. The fixture should exist in the native syntax of every supported SIEM, and the analyzer should record the capability result independently per target.

| ID | Major rule family | Required semantics | Sigma | SPL | KQL | EQL | AQL | YARA-L | CQL | Wazuh |
|---|---|---|---|---|---|---|---|---|---|---|
| RF-01 | Single event | One event type and one or more field predicates | selection | search | where | event where | WHERE | events/condition | field predicate | field/match |
| RF-02 | Boolean field logic | Nested `AND`, `OR`, and `NOT` with precedence | condition expression | parentheses/search/where | parentheses/where | where expression | WHERE expression | event condition | case/boolean pipeline | multiple XML elements |
| RF-03 | Value lists | `IN`, `has_any`, wildcard lists, regex alternatives | YAML lists/modifiers | `IN`, wildcards | `in`, `has_any` | list predicates | `IN`, `ILIKE` | regex/OR | regex/case | PCRE2 alternation |
| RF-04 | Exclusion | Allowlists, filters, trusted users, approved paths | filter selection | lookup/where NOT | leftanti/not | negated stage | NOT/WHERE | `not` event logic | negated pipeline | negate/if conditions |
| RF-05 | Count threshold | N matching events in a time window | correlation/count | stats count | summarize count | threshold rule | HAVING COUNT | `#event >= N` | groupBy count | frequency/timeframe |
| RF-06 | Entity grouping | Group by user, host, source IP, account, or key | correlation group | stats by | summarize by | sequence by | GROUP BY | match variables | groupBy | same_* |
| RF-07 | Ordered sequence | A then B then C, with a maximum span | correlation rule | transaction/streamstats | timestamp/join logic | sequence/maxspan | subqueries/correlation | event variables/timestamps | pipeline stages | parent/chained rules |
| RF-08 | Cross-source join | Join process, network, identity, or cloud streams | correlation metadata | join/lookup | join/union | multi-event sequence | subquery/function | event-variable equality | join/lookup | if_matched relationships |
| RF-09 | Aggregation | count, distinct count, sum, set/list, min/max, aliases | correlation aggregation | stats/dc/values | summarize/make_set | threshold/outcome | SUM/COUNT/HAVING | outcome aggregates | groupBy functions | frequency counters |
| RF-10 | Lookup/enrichment | Threat intel, account lists, asset data, IOC context | pipeline/lookup metadata | lookup/inputlookup | externaldata/watchlist | enrichment integration | X-Force/functions | graph/entity joins | lookup files | decoder/context rules |
| RF-11 | Absence | A occurs and B does not occur | negative correlation | transaction/NOT | leftanti/! | until/negated sequence | NOT/subquery | `!$event` | negated pipeline | if_matched plus negation |
| RF-12 | Risk/outcome | Calculate score, severity, custom alert details | metadata/level | eval/risk fields | extend/entity/custom details | rule metadata | magnitude/functions | outcome/condition | case/eval | level/description |
| RF-13 | Baseline/anomaly | Deviates from historical or peer behavior | correlation/anomaly metadata | predict/anomalydetection | series decomposition/anomaly | ML rule configuration | reference sets/statistics | risk/outcome logic | percentile/baseline functions | frequency tuning |
| RF-14 | Composite detection | Combine existing detections or findings | correlation rules | saved search/correlation | alert joins | composite EQL | offense/rule correlation | composite detections | alert correlation | if_matched_sid/group |
| RF-15 | Context-aware IOC | Event matched against graph/feed/entity context | enrichment pipeline | lookup/threat-intel | watchlist/threat-intel join | enrichment rule | X-Force/reference set | Entity Graph joins | lookup package | CDB/decoder context |
| RF-16 | Stateful/chained rule | Previous rule result drives the next rule | correlation chain | transaction/correlation | analytic rule chaining | sequence | custom rule/offense | composite condition | chained pipeline | if_sid/if_matched_sid |
| RF-17 | Windowing and suppression | Lookback, schedule, suppression, cooldown | correlation metadata | earliest/latest/suppression | interval/lookback/suppression | rule schedule/interval | LAST/scheduled search | match window | query window | timeframe/frequency |
| RF-18 | Entity and alert output | Host/user/IP mapping and analyst-facing details | metadata/tags | eval/risk output | entity mapping/custom details | outcome fields | selected aliases | outcome variables | event fields | description/groups |

### Required Family Fixtures By SIEM

The following fixture IDs are the minimum major-rule set. A future fixture file should contain one source rule per cell, not just one example per vendor.

#### Sigma

`RF-01`, `RF-02`, `RF-03`, `RF-04`, `RF-05`, `RF-06`, `RF-07`, `RF-08`, `RF-09`, `RF-10`, `RF-11`, `RF-12`, `RF-13`, `RF-14`, `RF-15`, `RF-16`, `RF-17`, `RF-18`.

Sigma fixtures must preserve `title`, `id`, `status`, `description`, `author`, `references`, `tags`, `logsource`, `detection`, `condition`, `falsepositives`, and `level` in addition to the detection expression.

#### Splunk Enterprise Security

`RF-01`: `index` plus field search; `RF-02`: nested `search` and `where`; `RF-03`: `IN`, wildcard, and `regex`; `RF-04`: `lookup` allowlist and `where NOT`; `RF-05`: `stats count`; `RF-06`: `stats ... by`; `RF-07`: `transaction` with `maxspan`; `RF-08`: `join` between process and network data; `RF-09`: `count`, `dc`, `values`, `sum`, aliases; `RF-10`: `lookup` and `inputlookup`; `RF-11`: `transaction` with missing end event; `RF-12`: `eval` risk score and notable fields; `RF-13`: `predict`/anomaly pipeline; `RF-14`: saved-search correlation; `RF-15`: threat-intelligence lookup; `RF-16`: transaction/correlation chain; `RF-17`: earliest/latest and suppression; `RF-18`: entity fields and adaptive-response metadata.

#### Microsoft Sentinel KQL

`RF-01`: table plus `where`; `RF-02`: nested boolean KQL; `RF-03`: `in`, `has_any`, regex; `RF-04`: `leftanti` approved-account join; `RF-05`: `summarize count`; `RF-06`: `summarize by`; `RF-07`: timestamp-ordered join; `RF-08`: `let` streams and `join`; `RF-09`: `count`, `dcount`, `make_set`, `min`, `max`; `RF-10`: watchlist/external data; `RF-11`: `leftanti` missing event; `RF-12`: `extend`, entity mapping, custom details; `RF-13`: `series_decompose_anomalies`; `RF-14`: alert/entity grouping; `RF-15`: threat-intel table join; `RF-16`: analytic-rule chaining; `RF-17`: interval, lookback, suppression; `RF-18`: entity mappings and alert customization.

#### Elastic Security EQL

`RF-01`: event category and predicate; `RF-02`: event expression; `RF-03`: list/wildcard/regex; `RF-04`: negated predicate; `RF-05`: threshold rule; `RF-06`: `sequence by`; `RF-07`: ordered `sequence` and `maxspan`; `RF-08`: event-variable equality; `RF-09`: threshold and rule aggregation; `RF-10`: enrich/lookup integration; `RF-11`: negated sequence stage; `RF-12`: rule risk metadata; `RF-13`: anomaly rule configuration; `RF-14`: detection-rule correlation; `RF-15`: threat-intel index join; `RF-16`: chained detection sequence; `RF-17`: rule interval/lookback; `RF-18`: alert fields and risk score.

#### IBM QRadar AQL

`RF-01`: event `WHERE`; `RF-02`: nested AQL predicates; `RF-03`: `IN`, `ILIKE`, `MATCHES`; `RF-04`: `NOT`, reference sets; `RF-05`: `HAVING COUNT`; `RF-06`: `GROUP BY`; `RF-07`: historical/correlation search; `RF-08`: event/flow/subquery relationship; `RF-09`: `COUNT`, `SUM`, `AVG`, aliases; `RF-10`: X-Force/reference-set functions; `RF-11`: missing-event correlation; `RF-12`: magnitude/category/rule output; `RF-13`: historical statistics; `RF-14`: custom-rule/offense correlation; `RF-15`: X-Force IP/URL/domain context; `RF-16`: rule/offense chaining; `RF-17`: `LAST` and scheduled search; `RF-18`: selected aliases and offense fields.

#### Google SecOps YARA-L 2.0

`RF-01`: one event variable; `RF-02`: event boolean expression; `RF-03`: regex, OR, CIDR; `RF-04`: `not` and zero-value exclusion; `RF-05`: `#event >= N`; `RF-06`: `match` variables; `RF-07`: timestamp-ordered event variables; `RF-08`: equality placeholders; `RF-09`: `count`, `count_distinct`, `sum`, `array_distinct`; `RF-10`: Entity Graph joins; `RF-11`: `!$event`; `RF-12`: `outcome` risk score; `RF-13`: outcome-based anomaly/risk aggregation; `RF-14`: composite detections; `RF-15`: IOC graph feeds; `RF-16`: sequential composite detections; `RF-17`: match windows and sliding windows; `RF-18`: outcome variables and detection details.

#### CrowdStrike Falcon LogScale CQL

`RF-01`: field predicate; `RF-02`: case/boolean pipeline; `RF-03`: regex and list matching; `RF-04`: negated pipeline; `RF-05`: `groupBy` count; `RF-06`: entity group keys; `RF-07`: ordered pipeline stages; `RF-08`: `join` and lookup; `RF-09`: count/distinct aggregation; `RF-10`: lookup files and packages; `RF-11`: negative case branch; `RF-12`: `case` risk output; `RF-13`: percentile/baseline pipeline; `RF-14`: alert/package correlation; `RF-15`: threat-intel lookup; `RF-16`: chained query stages; `RF-17`: query windows; `RF-18`: output fields and alert metadata.

#### Wazuh Ruleset XML

`RF-01`: `<field>`, `<match>`, `<program_name>`; `RF-02`: multiple XML predicates; `RF-03`: PCRE2 alternation; `RF-04`: `negate="yes"`; `RF-05`: `frequency`/`timeframe`; `RF-06`: `<same_srcip>`, `<same_user>`, `<same_field>`; `RF-07`: parent rule chain; `RF-08`: `if_sid`, `if_matched_sid`, `if_group`; `RF-09`: frequency counters; `RF-10`: decoder/CDB context; `RF-11`: chained negative conditions; `RF-12`: level, description, groups; `RF-13`: frequency tuning; `RF-14`: composite custom rules; `RF-15`: CDB/reference context; `RF-16`: chained rule IDs; `RF-17`: timeframe/frequency; `RF-18`: MITRE IDs, groups, and descriptions.

### Completion Standard

The tool should not be called major-rule capable until every `RF-01` through `RF-18` family has:

- A fixture for every supported dialect.
- A parser test.
- A structured-model assertion.
- A fidelity assertion.
- A renderer or explicit unsupported result.
- A round-trip test for unchanged source.
- A negative test proving that unsupported semantics are not silently dropped.
