# Complex SIEM Rule Test Pack

These are safe, representative detection rules for exercising RuleForge's
current eight ready dialects. They are detection logic only; they do not run
commands or contain payloads.

The checked-in fixtures are regression-tested against the local evaluator. The
expected result for every pair is:

| Dialect | Positive fixture | Negative fixture |
|---|---|---|
| Sentinel / KQL | `matched` | `no_match` |
| Sigma | `matched` | `no_match` |
| Splunk SPL | `matched` | `no_match` |
| QRadar AQL | `matched` | `no_match` |
| Elastic EQL | `matched` | `no_match` |
| Wazuh XML | `matched` | `no_match` |
| Chronicle YARA-L | `matched` | `no_match` |
| CrowdStrike FQL | `matched` | `no_match` |

The field names are intentionally realistic but environment-specific. In a
real SIEM, map them to the fields used by your data model before deployment.
Paste each rule into **Import & Explain**, choose the matching dialect, and
then use **Render**, **Validate**, and **Save version**.

## 1. Microsoft Sentinel / KQL — credential access followed by lateral movement

```kql
let LSASSAccess =
SecurityEvent
| where EventID == 10
| where TargetImage endswith @"\lsass.exe"
| project LSASSTime=TimeGenerated, Computer, Account, SourceImage, SourceIp;

let LateralMovement =
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| project LoginTime=TimeGenerated, Computer, Account, IpAddress;

LSASSAccess
| join kind=inner (LateralMovement) on Computer, Account
| where LoginTime between (LSASSTime .. LSASSTime + 10m)
| summarize Hits=count(), FirstSeen=min(LSASSTime), SourceIPs=make_set(SourceIp) by Computer, Account
| where Hits >= 1
| extend DetectionName="Credential Access Followed By NTLM Lateral Movement"
```

Tests: `let` bindings, temporal join, projection aliases, aggregation, set
aggregation, post-aggregate filtering, and derived fields.

### Positive fixture — JSONL

```jsonl
{"EventID":10,"TargetImage":"C:\\Windows\\System32\\lsass.exe","TimeGenerated":"2026-10-25T10:00:00Z","Computer":"DC01","Account":"alice","SourceImage":"C:\\Tools\\procdump.exe","SourceIp":"203.0.113.50"}
{"EventID":4624,"LogonType":3,"AuthenticationPackageName":"NTLM","TimeGenerated":"2026-10-25T10:05:00Z","Computer":"DC01","Account":"alice","IpAddress":"203.0.113.50"}
```

### Negative fixture — JSONL

```jsonl
{"EventID":10,"TargetImage":"C:\\Windows\\System32\\lsass.exe","TimeGenerated":"2026-10-25T10:00:00Z","Computer":"DC01","Account":"alice","SourceImage":"C:\\Windows\\System32\\taskmgr.exe","SourceIp":"10.10.10.20"}
{"EventID":4624,"LogonType":3,"AuthenticationPackageName":"Kerberos","TimeGenerated":"2026-10-25T10:05:00Z","Computer":"DC01","Account":"alice","IpAddress":"10.10.10.20"}
```

The negative case uses the wrong authentication package, so the second
pipeline does not qualify as the lateral-movement side of the join.

## 2. Sigma — suspicious Office-to-PowerShell execution

```yaml
title: Suspicious Office Child Process With Encoded or Downloading PowerShell
description: Office applications spawn a scripting process using an encoded or remote-download command line.
author: Detection Engineering
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\OUTLOOK.EXE'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
    selection_payload:
        CommandLine|contains|all:
            - '-enc'
            - 'DownloadString'
    filter_system:
        User|endswith: '$'
    condition: selection_parent and selection_child and selection_payload and not filter_system
```

Tests: multiple selections, value lists, `contains|all`, an exclusion, and a
compound condition.

### Positive fixture — JSONL

```jsonl
{"UtcTime":"2026-10-25T10:15:00Z","ParentImage":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -enc DownloadString https://example.com/a","User":"alice"}
```

### Negative fixture — JSONL

```jsonl
{"UtcTime":"2026-10-25T10:15:00Z","ParentImage":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -enc DownloadString https://example.com/a","User":"SYSTEM$"}
```

The negative case is intentionally excluded by `filter_system`.

## 3. Splunk SPL — failed RDP burst followed by a successful login

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624) Logon_Type=10
| stats count(eval(EventCode=4625)) as Fails,
        count(eval(EventCode=4624)) as Successes,
        dc(src_ip) as Sources,
        dc(Account_Name) as Users
  by Account_Name
| where Fails > 10 AND Successes > 0 AND Sources > 2
| eval Risk=if(Fails > 25, "critical", "high")
| sort - Fails
| head 20
```

Tests: boolean search precedence, conditional counts, distinct counts,
grouping, post-aggregate filtering, derived risk, sorting, and limiting.

### Positive fixture — JSONL

```jsonl
{"_time":"2026-10-25T11:00:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:01:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:02:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.11"}
{"_time":"2026-10-25T11:03:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.11"}
{"_time":"2026-10-25T11:04:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.12"}
{"_time":"2026-10-25T11:05:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.12"}
{"_time":"2026-10-25T11:06:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:07:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.11"}
{"_time":"2026-10-25T11:08:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.12"}
{"_time":"2026-10-25T11:09:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:10:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.11"}
{"_time":"2026-10-25T11:11:00Z","EventCode":4624,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.12"}
```

### Negative fixture — JSONL

```jsonl
{"_time":"2026-10-25T11:00:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:01:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:02:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:03:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:04:00Z","EventCode":4625,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
{"_time":"2026-10-25T11:05:00Z","EventCode":4624,"Logon_Type":10,"Account_Name":"alice","src_ip":"203.0.113.10"}
```

The negative case has too few failures and only one source IP.

## 4. IBM QRadar / AQL — multi-target authentication spray

```sql
SELECT sourceip,
       username,
       COUNT(*) AS attempts,
       COUNT(DISTINCT destinationip) AS targets,
       SUM(bytes) AS total_bytes
FROM events
WHERE qid IN (1, 2, 3)
  AND username NOT LIKE 'svc_%'
  AND destinationport BETWEEN 1 AND 1024
GROUP BY sourceip, username
HAVING COUNT(*) > 20 AND COUNT(DISTINCT destinationip) >= 3
ORDER BY attempts DESC
LIMIT 50
```

Tests: nested boolean predicates, `IN`, function calls, `NOT LIKE`, numeric
ranges, multiple grouping keys, distinct aggregation, `HAVING`, ordering, and
limiting.

### Positive fixture — JSONL

```jsonl
{"starttime":"2026-10-25T15:00:00Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":1200}
{"starttime":"2026-10-25T15:00:10Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":1300}
{"starttime":"2026-10-25T15:00:20Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":1400}
{"starttime":"2026-10-25T15:00:30Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":1500}
{"starttime":"2026-10-25T15:00:40Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":1600}
{"starttime":"2026-10-25T15:00:50Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":1700}
{"starttime":"2026-10-25T15:01:00Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":1800}
{"starttime":"2026-10-25T15:01:10Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":1900}
{"starttime":"2026-10-25T15:01:20Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":2000}
{"starttime":"2026-10-25T15:01:30Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":2100}
{"starttime":"2026-10-25T15:01:40Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.12","destinationport":443,"bytes":2200}
{"starttime":"2026-10-25T15:01:50Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.12","destinationport":443,"bytes":2300}
{"starttime":"2026-10-25T15:02:00Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.12","destinationport":443,"bytes":2400}
{"starttime":"2026-10-25T15:02:10Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.12","destinationport":443,"bytes":2500}
{"starttime":"2026-10-25T15:02:20Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.12","destinationport":443,"bytes":2600}
{"starttime":"2026-10-25T15:02:30Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":2700}
{"starttime":"2026-10-25T15:02:40Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":2800}
{"starttime":"2026-10-25T15:02:50Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.12","destinationport":443,"bytes":2900}
{"starttime":"2026-10-25T15:03:00Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":3000}
{"starttime":"2026-10-25T15:03:10Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":3100}
{"starttime":"2026-10-25T15:03:20Z","sourceip":"198.51.100.40","username":"alice","qid":1,"destinationip":"10.20.1.12","destinationport":443,"bytes":3200}
```

### Negative fixture — JSONL

```jsonl
{"starttime":"2026-10-25T15:00:00Z","sourceip":"198.51.100.41","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":1200}
{"starttime":"2026-10-25T15:01:00Z","sourceip":"198.51.100.41","username":"alice","qid":1,"destinationip":"10.20.1.10","destinationport":443,"bytes":1300}
{"starttime":"2026-10-25T15:02:00Z","sourceip":"198.51.100.41","username":"alice","qid":1,"destinationip":"10.20.1.11","destinationport":443,"bytes":1400}
```

The negative case has fewer than 20 attempts and fewer than three targets.

## 5. Elastic Security / EQL — Office, PowerShell, and outbound connection chain

```eql
sequence by host.id with maxspan=15m
  [process where process.name in ("winword.exe", "excel.exe") and process.parent.name == "explorer.exe"]
  [process where process.name like~ "powershell.exe" and stringcontains(process.command_line, "-enc")]
  [network where destination.port in (80, 443) and event.type == "connection"]
until [process where event.category == "process" and process.name == "rundll32.exe"]
```

Tests: keyed ordered sequence, three event stages, `maxspan`, `in`,
case-insensitive matching, string function use, network/process category
changes, and an `until` boundary.

### Positive fixture — JSONL

```jsonl
{"@timestamp":"2026-10-25T12:00:00Z","event":{"category":"process","type":"start"},"host":{"id":"WS-01"},"process":{"name":"winword.exe","parent":{"name":"explorer.exe"}}}
{"@timestamp":"2026-10-25T12:04:00Z","event":{"category":"process","type":"start"},"host":{"id":"WS-01"},"process":{"name":"PowerShell.exe","command_line":"powershell.exe -enc DownloadString https://example.com/a","parent":{"name":"winword.exe"}}}
{"@timestamp":"2026-10-25T12:07:00Z","event":{"category":"network","type":"connection"},"host":{"id":"WS-01"},"process":{"name":"network","parent":{"name":"network"}},"destination":{"port":443}}
```

### Negative fixture — JSONL

```jsonl
{"@timestamp":"2026-10-25T12:00:00Z","event":{"category":"process","type":"start"},"host":{"id":"WS-02"},"process":{"name":"winword.exe","parent":{"name":"explorer.exe"}}}
{"@timestamp":"2026-10-25T12:04:00Z","event":{"category":"process","type":"start"},"host":{"id":"WS-02"},"process":{"name":"notepad.exe","parent":{"name":"winword.exe"}}}
{"@timestamp":"2026-10-25T12:07:00Z","event":{"category":"network","type":"connection"},"host":{"id":"WS-02"},"process":{"name":"network","parent":{"name":"network"}},"destination":{"port":53}}
```

The negative case breaks both the PowerShell step and the destination-port
condition.

## 6. Wazuh XML — encoded PowerShell burst from one source and user

```xml
<group name="windows,execution,credential_access,">
  <rule id="100900" level="14" frequency="3" timeframe="600">
    <if_matched_sid>100210</if_matched_sid>
    <same_source_ip />
    <same_field name="win.eventdata.User" />
    <match>-enc</match>
    <description>Repeated suspicious PowerShell activity from one source and user</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>
</group>
```

Tests: parent-rule dependency, field substring matching, MITRE metadata,
frequency/timeframe correlation, and two grouping constraints.

### Positive fixture — JSONL

```jsonl
{"timestamp":"2026-10-25T13:00:00Z","srcip":"203.0.113.60","full_log":"powershell.exe -enc DownloadString https://example.com/a","win":{"eventdata":{"User":"alice","Image":"powershell.exe","CommandLine":"powershell.exe -enc DownloadString https://example.com/a"}}}
{"timestamp":"2026-10-25T13:02:00Z","srcip":"203.0.113.60","full_log":"powershell.exe -enc AAAA","win":{"eventdata":{"User":"alice","Image":"powershell.exe","CommandLine":"powershell.exe -enc AAAA"}}}
{"timestamp":"2026-10-25T13:04:00Z","srcip":"203.0.113.60","full_log":"powershell.exe -enc DownloadString https://example.com/b","win":{"eventdata":{"User":"alice","Image":"powershell.exe","CommandLine":"powershell.exe -enc DownloadString https://example.com/b"}}}
```

### Negative fixture — JSONL

```jsonl
{"timestamp":"2026-10-25T13:00:00Z","srcip":"203.0.113.61","full_log":"powershell.exe -NoProfile -Command Get-Process","win":{"eventdata":{"User":"alice","Image":"powershell.exe","CommandLine":"powershell.exe -NoProfile -Command Get-Process"}}}
{"timestamp":"2026-10-25T13:02:00Z","srcip":"203.0.113.61","full_log":"powershell.exe -NoProfile -Command Get-Service","win":{"eventdata":{"User":"alice","Image":"powershell.exe","CommandLine":"powershell.exe -NoProfile -Command Get-Service"}}}
```

The positive fixture shows three events sharing source and user. The Wazuh
correlation rule assumes parent SID `100210` exists in the deployed ruleset.

## 7. Google Chronicle / YARA-L — identity escalation followed by sensitive download

```yaral
rule identity_escalation_then_sensitive_download {
  meta:
    author = "Detection Engineering"
    description = "A user has repeated successful logins, performs an administrative change, then downloads a sensitive object."
    severity = "HIGH"
    mitre_attack_tactic = "Privilege Escalation"
  events:
    $login.metadata.event_type = "USER_LOGIN"
    $login.principal.user.userid = $user

    $admin.metadata.event_type = "ADMIN_ACTIVITY"
    $admin.principal.user.userid = $user
  match:
    $user over 30m
  outcome:
    $login_count = count($login.metadata.event_type)
    $resources = array_distinct($admin.metadata.event_type)
  condition:
    $login and $admin and #login >= 3
}
```

Tests: two-event correlation, shared variable binding, match window, outcome
count, distinct array outcome, and threshold condition.

### Positive fixture — JSONL

```jsonl
{"metadata":{"event_type":"USER_LOGIN","event_timestamp":"2026-10-25T14:00:00Z"},"security_result":{"action":"ALLOW"},"principal":{"user":{"userid":"alice@example.com"}}}
{"metadata":{"event_type":"USER_LOGIN","event_timestamp":"2026-10-25T14:05:00Z"},"security_result":{"action":"ALLOW"},"principal":{"user":{"userid":"alice@example.com"}}}
{"metadata":{"event_type":"USER_LOGIN","event_timestamp":"2026-10-25T14:10:00Z"},"security_result":{"action":"ALLOW"},"principal":{"user":{"userid":"alice@example.com"}}}
{"metadata":{"event_type":"ADMIN_ACTIVITY","event_timestamp":"2026-10-25T14:15:00Z"},"principal":{"user":{"userid":"alice@example.com"}},"target":{"resource":{"name":"Global Admin role"}}}
```

### Negative fixture — JSONL

```jsonl
{"metadata":{"event_type":"USER_LOGIN","event_timestamp":"2026-10-25T14:00:00Z"},"security_result":{"action":"ALLOW"},"principal":{"user":{"userid":"alice@example.com"}}}
{"metadata":{"event_type":"USER_LOGIN","event_timestamp":"2026-10-25T14:05:00Z"},"security_result":{"action":"ALLOW"},"principal":{"user":{"userid":"alice@example.com"}}}
{"metadata":{"event_type":"ADMIN_ACTIVITY","event_timestamp":"2026-10-25T14:10:00Z"},"principal":{"user":{"userid":"bob@example.com"}},"target":{"resource":{"name":"Global Admin role"}}}
```

The negative case does not share the same user across the two event streams
and also has fewer than three login events.

## 8. CrowdStrike FQL — suspicious encoded script launched by Office

```fql
platform_name:Windows+
event_simpleName:'ProcessRollup2'+
ParentBaseFileName:'WINWORD.EXE'+
FileName:'powershell.exe'+
CommandLine:'EncodedCommand'+
!UserName:'SYSTEM'
```

Tests: platform constraint, exact event type, multiple field constraints, exact
command matching, and a negated service-account exclusion.

### Positive fixture — JSONL

```jsonl
{"platform_name":"Windows","event_simpleName":"ProcessRollup2","ParentBaseFileName":"WINWORD.EXE","FileName":"powershell.exe","CommandLine":"EncodedCommand","UserName":"alice"}
```

### Negative fixture — JSONL

```jsonl
{"platform_name":"Windows","event_simpleName":"ProcessRollup2","ParentBaseFileName":"WINWORD.EXE","FileName":"powershell.exe","CommandLine":"EncodedCommand","UserName":"SYSTEM"}
```

The negative case is excluded by the `!UserName:'SYSTEM'` clause.

## Suggested UI test order

1. Paste each rule into **Import & Explain**.
2. Confirm the parsed outline and diagnostics.
3. Load it into the Workbench.
4. Switch the target dialect and press **Render**.
5. Press **Validate**.
6. Save a version in **History**.
7. Copy the **Positive fixture** into **Datasets** as a JSONL dataset and save
   it with a label such as `positive`.
8. Copy the **Negative fixture** into a second JSONL dataset and save it with a
   label such as `negative`.
9. In **Workbench** or **Test Runs**, select each dataset, choose the expected
   verdict, and click **Run and save evidence**.

The local evaluator is intentionally bounded. A complex rule may correctly
render and validate while returning `not_evaluated` for vendor-specific joins,
sequence timing, or appliance-only behavior. That is expected and should be
treated as an evidence boundary, not as a successful vendor-runtime proof.

For the sequence, join, Wazuh parent-rule, and Chronicle correlation examples,
the fixture is still valuable for parser/render testing and may produce
`not_evaluated` locally. That is expected because the local evaluator does not
pretend to be a complete vendor runtime.
