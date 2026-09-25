# RuleForge acceptance corpus — 10 real rules, 7 targets, 70 cells.
#
# This is the Phase 0 deliverable of docs/ruleforge-redesign-plan.md. It is NOT a set of
# unit-test expectations written to pass. It is a frozen statement of what each rule means
# and what each target can honestly be asked to produce, and every Phase 4-9 vertical
# slice is measured against it.
#
# The rules here are the ten real rules supplied by the maintainer. They are the acceptance
# corpus, NOT the source of the design: the RuleIR kernel is derived from first principles
# (see plan section 6). These rules test whether that derivation was right.
#
# `support` vocabulary, and the only three values allowed:
#   native       - the target expresses the construct with its own construct
#   equivalent   - an exact composition of registered target capabilities, no semantic change
#   refused      - no faithful path; the tool must emit an EMPTY artifact and a named reason
#
# There is deliberately no "partial produces a downloadable rule" value. That is the bug
# class this redesign exists to end. A projection may be shown as a non-deployable
# blueprint; it may never be labelled equivalent.

TARGETS = ["splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh"]

# ---------------------------------------------------------------------------
# TIER 1 - pipeline-shaped rules
# ---------------------------------------------------------------------------

TIER1 = {
    "t1_splunk_lsass_network": {
        "target": "splunk",
        "shape": "filter -> aggregate -> filter on the aggregate",
        "source": "index=windows EventCode=10 | where TargetImage=\"*lsass.exe*\" | stats count by host SourceImage TargetImage User | where count >= 1",
        "primitives": ["read", "filter", "frame", "aggregate", "filter", "emit"],
        "why": "The post-aggregate filter is unrepresentable in the current v1 model, which is how it was silently reduced to one predicate and graded exact.",
    },
    "t1_sentinel_impossible_travel": {
        "target": "sentinel",
        "shape": "two named measures + time bin + predicate over measures",
        "source": "SigninLogs | where ResultType == 0 | summarize Failed=countif(ResultType != 0), Success=countif(ResultType == 0) by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m) | where Failed >= 5 and Success >= 1",
        "primitives": ["read", "filter", "frame", "aggregate", "filter", "emit"],
        "why": "v1 cannot hold two independently named measures, so the whole correlate collapses to 0 conditions and fidelity=unsupported.",
    },
    "t1_wazuh_powershell_chain": {
        "target": "wazuh",
        "shape": "ordered stages with a shared window",
        "source": "Sysmon Event 1 AND Image endswith powershell.exe AND CommandLine matches (-enc|-encodedcommand) AND ParentImage endswith (WINWORD|OUTLOOK).EXE",
        "primitives": ["read", "filter", "pattern", "emit"],
        "why": "Wazuh expresses this as a parent/child rule dependency, not one query.",
    },
    "t1_qradar_brute_force_success": {
        "target": "qradar",
        "shape": "stateful WHEN / FOLLOWED BY with a shared window",
        "source": "WHEN >= 10 Authentication Failure events FROM same Source IP WITHIN 5 minutes FOLLOWED BY Authentication Success AND Privileged Command WITHIN 10 minutes",
        "primitives": ["read", "filter", "frame", "pattern", "emit"],
        "why": "This is a QRadar CRE event-sequence rule. AQL cannot express it and must not be offered in its place.",
    },
    "t1_yaral_process_conn": {
        "target": "google_secops",
        "shape": "two event streams, join, outcome/risk",
        "source": "$proc.metadata.event_type = \"PROCESS_LAUNCH\"; $net.metadata.event_type = \"NETWORK_CONNECTION\"; $net.principal.hostname = $proc.principal.hostname; match: $proc over 5m; outcome: $risk = 80",
        "primitives": ["read", "filter", "frame", "join", "derive", "emit"],
        "why": "Multi-stream correlation plus a typed outcome block.",
    },
}

# ---------------------------------------------------------------------------
# TIER 2 - the harder batch. Each one forced a correction to an earlier draft.
# ---------------------------------------------------------------------------

TIER2 = {
    "t2_wazuh_rule_bundle": {
        "target": "wazuh",
        "shape": "a PACKAGE of two rules with a dependency edge and a stateful sliding counter",
        "source": (
            '<group name="windows,credential_access,lateral_movement,">\n'
            '  <rule id="100210" level="10">\n'
            '    <if_group>sysmon_event_10</if_group>\n'
            '    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\\\lsass\\.exe$</field>\n'
            '    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)(0x1fffff|0x1010|0x1410|0x143a)</field>\n'
            '    <mitre><id>T1003.001</id></mitre>\n'
            '  </rule>\n'
            '  <rule id="100211" level="15" frequency="2" timeframe="300">\n'
            '    <if_matched_sid>100210</if_matched_sid>\n'
            '    <same_srcip />\n'
            '    <mitre><id>T1003.001</id></mitre>\n'
            '  </rule>\n'
            '</group>'
        ),
        "primitives": ["read", "filter", "frame", "aggregate", "emit"],
        "package_units": 2,
        "package_dependency": "100211 -> 100210",
        "unresolved_external_dependency": "sysmon_event_10",
        "why": "Correlator state over prior rule ALERTS, not events. Forced RuleSet to become a package rather than a graph node.",
    },
    "t2_splunk_tstats_subquery": {
        "target": "splunk",
        "shape": "accelerated summary source, derived binding, subquery, non-temporal join, second aggregation, typed eval",
        "source": (
            '| tstats summariesonly=t count values(Processes.process) as process values(Processes.dest) as dest '
            'from datamodel=Endpoint.Processes where Processes.process_name IN ("procdump.exe","rundll32.exe") '
            'AND Processes.process="*lsass.exe*" by Processes.dest Processes.user _time span=5m\n'
            '| rename Processes.dest as dest Processes.user as user\n'
            '| eval credential_access=1\n'
            '| join type=inner dest user [ | tstats summariesonly=t count values(Authentication.src) as src '
            'from datamodel=Authentication.Authentication where Authentication.action="success" '
            'AND Authentication.authentication_method="NTLM" by Authentication.dest Authentication.user _time span=5m '
            '| rename Authentication.dest as dest Authentication.user as user | eval lateral_movement=1 ]\n'
            '| stats min(_time) as firstTime max(_time) as lastTime max(credential_access) as credential_access '
            'max(lateral_movement) as lateral_movement values(process) as processes by dest user\n'
            '| where credential_access=1 AND lateral_movement=1\n'
            '| eval risk_score=90 mitre_technique="T1003.001,T1021.002"'
        ),
        "primitives": ["read", "filter", "frame", "aggregate", "derive", "join", "aggregate", "filter", "emit"],
        "critical_semantics": [
            "the two span=5m clauses are BUCKETS, not a correlation window",
            "the join has NO temporal constraint",
            "summariesonly reads an acceleration summary, not raw events",
            "the final stats proves per-entity co-occurrence, NOT that LSASS preceded NTLM",
        ],
        "why": "Forced a real distinction between bucketing and correlation, and between a temporal and a non-temporal join.",
    },
    "t2_sentinel_temporal_join": {
        "target": "sentinel",
        "shape": "two bindings, equijoin, asymmetric inclusive temporal predicate, joined-row aggregate",
        "source": (
            'let LSASSAccess = SecurityEvent | where EventID == 10 | where TargetImage endswith @"\\lsass.exe" '
            '| project LSASSTime=TimeGenerated, Computer, Account, SourceImage, SourceIp, TargetImage;\n'
            'let LateralMovement = SecurityEvent | where EventID == 4624 | where LogonType == 3 '
            '| where AuthenticationPackageName == "NTLM" '
            '| project LoginTime=TimeGenerated, Computer, Account, IpAddress;\n'
            'LSASSAccess | join kind=inner LateralMovement on Computer, Account '
            '| where LoginTime between (LSASSTime .. LSASSTime + 10m) '
            '| summarize LSASSAccessCount=count(), FirstSeen=min(LSASSTime), LastSeen=max(LoginTime), '
            'SourceIPs=make_set(SourceIp) by Computer, Account | where LSASSAccessCount >= 1 '
            '| extend DetectionName="Credential Access Followed By NTLM Lateral Movement"'
        ),
        "primitives": ["read", "filter", "derive", "join", "filter", "frame", "aggregate", "filter", "derive", "emit"],
        "critical_semantics": [
            "between is INCLUSIVE on both ends: LSASSTime <= LoginTime <= LSASSTime + 10m",
            "count() counts JOINED PAIRS, not distinct LSASS events",
        ],
        "why": "A general relational join plus a directional temporal predicate. v1 has no join node at all.",
    },
    "t2_qradar_grouped_aql": {
        "target": "qradar",
        "shape": "grouped HISTORICAL search - NOT an event sequence",
        "source": (
            "SELECT sourceip, destinationip, username, COUNT(*) AS event_count, "
            "MIN(starttime) AS first_seen, MAX(starttime) AS last_seen FROM events WHERE "
            "(QIDNAME(qid) ILIKE '%LSASS%' OR LOGSOURCENAME(logsourceid) ILIKE '%Sysmon%' "
            "AND UTF8(payload) ILIKE '%lsass.exe%') OR "
            "(QIDNAME(qid) ILIKE '%NTLM%' AND UTF8(payload) ILIKE '%Logon Type: 3%') "
            "GROUP BY sourceip, destinationip, username HAVING COUNT(*) >= 2 ORDER BY last_seen DESC"
        ),
        "primitives": ["read", "filter", "frame", "aggregate", "filter", "arrange", "emit"],
        "critical_semantics": [
            "the OR means LSASS OR (Sysmon AND lsass) OR (NTLM AND logon3); two rows satisfying ONLY the first branch meet COUNT(*) >= 2",
            "there is NO LAST/START/STOP, so as pasted it is not a complete standalone AQL artifact",
            "a real-time detecting rule needs QRadar CRE, which is an engine, not a file format",
        ],
        "why": "Forced the QRadar AQL-vs-CRE boundary and the refusal that goes with it.",
    },
    "t2_yaral_cross_event": {
        "target": "google_secops",
        "shape": "event-variable relationship with a CROSS-EVENT timestamp comparison",
        "source": (
            'rule CredentialAccess_NTLM_LateralMovement {\n'
            '  meta:\n'
            '    author = "SOC Detection Engineering"\n'
            '    severity = "HIGH"\n'
            '  events:\n'
            '    $lsass.metadata.event_type = "PROCESS_ACCESS"\n'
            '    $lsass.target.process.file.full_path = /\\\\lsass\\.exe$/ nocase\n'
            '    $lsass.principal.hostname = $host\n'
            '    $login.metadata.event_type = "USER_LOGIN"\n'
            '    $login.extensions.auth.type = "NTLM"\n'
            '    $login.principal.hostname = $host\n'
            '    $lsass.metadata.event_timestamp <= $login.metadata.event_timestamp\n'
            '  match:\n'
            '    $host over 10m\n'
            '  condition:\n'
            '    $lsass and $login\n'
            '}'
        ),
        "primitives": ["read", "filter", "frame", "join", "filter", "emit"],
        "critical_semantics": [
            "the cross-event timestamp comparison is a SCOPED EXPRESSION, not a stage transition",
            "it must NOT be modelled as a Pattern/Sequence: that would wrongly couple pairing, order and span",
        ],
        "source_defect": "the supplied meta block is not valid YARA-L key/value syntax, so the literal source must be refused while the semantic core stays modelable",
        "why": "This is what killed the EventRelation node. It is Frame + Join + Filter.",
    },
}

RULES = {**TIER1, **TIER2}


def rule_ids():
    return sorted(RULES)


def cells():
    """The 10 x 7 matrix. Every cell must be explicitly declared by expect()."""
    return [(rid, target) for rid in rule_ids() for target in TARGETS]
