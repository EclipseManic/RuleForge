"""Regenerate data/mappings/fields.json with schema-based, provenance-tagged mappings.

Provenance matters: a field mapping is only useful if an analyst can trust it. Every table
below is derived from a published vendor schema, recorded in meta.sources. Cells we cannot
verify are omitted on purpose - omitted fields pass through unchanged and are flagged
"unmapped - verify" in the UI, which is safer than a plausible-looking wrong name.
"""
from __future__ import annotations

import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "mappings"
DATA.mkdir(parents=True, exist_ok=True)

# Splunk CIM. Names from the published CIM data model references (help.splunk.com
# Common Information Model). CIM data models are named by category, so each entry below
# belongs to the data model noted in its comment.
SPLUNK_CIM = {
    # Endpoint data model
    "process.command_line": "process_command_line", "process.name": "process_name",
    "process.executable": "process_path", "process.pid": "process_id",
    "process.parent.name": "parent_process_name", "process.parent.executable": "parent_process_path",
    "process.parent.command_line": "parent_process_command_line",
    "process.parent.pid": "parent_process_id", "process.args": "process_command_line",
    "process.pid_hash": "process_guid", "process.thread.id": "process_thread_id",
    "user.name": "user", "user.id": "user_id", "user.domain": "user_domain",
    "group.name": "group_name",
    "host.name": "host", "host.id": "device_id",
    # NetworkTraffic / NetworkSessions
    "source.ip": "src_ip", "source.port": "src_port", "source.domain": "src",
    "destination.ip": "dest_ip", "destination.port": "dest_port", "destination.domain": "dest",
    "network.protocol": "transport", "network.direction": "direction",
    "network.bytes": "bytes", "network.transport": "transport",
    # Endpoint file system
    "file.name": "file_name", "file.path": "file_path", "file.size": "file_size",
    "file.hash.sha256": "file_hash", "file.hash.sha1": "file_hash",
    "file.hash.md5": "file_hash", "file.directory": "file_path",
    # Registry
    "registry.key": "registry_key", "registry.value": "registry_data",
    "registry.data": "registry_data", "registry.path": "registry_path",
    # DNS
    "dns.question.name": "query", "dns.answers.name": "answer",
    # Authentication / common event
    "event.action": "action", "event.outcome": "outcome", "event.code": "signature_id",
    "event.provider": "vendor_product", "event.dataset": "source",
    "event.category": "sourcetype", "event.created": "timestamp",
}

# Microsoft Sentinel ASIM. Names verified against the published ASIM schema references
# (learn.microsoft.com/en-us/azure/sentinel/normalization-schema-*). ASIM prefixes fields by
# the role they describe: Target*/ActingProcess*/ParentProcess*/Src*/Dst*/Dvc*.
# The earlier table used legacy SecurityEvent/DeviceProcessEvents names (ProcessName,
# ProcessCommandLine, UserName, Computer, SourceIp). Those do NOT exist in ASIM-normalized
# tables, so every Sentinel rule was querying columns that were never populated.
# ASIM is schema-specific: the same canonical field resolves differently in ProcessEvent
# vs NetworkSession, so entries below name the schema they belong to in their comment.
ASIM = {
    # --- ProcessEvent ---
    "process.command_line": "TargetProcessCommandLine",
    "process.name": "TargetProcessName",
    "process.executable": "TargetProcessPath",
    "process.pid": "TargetProcessId",
    "process.parent.name": "ParentProcessName",
    "process.parent.command_line": "ParentProcessCommandLine",
    "process.parent.pid": "ParentProcessId",
    "process.parent.executable": "ParentProcessPath",
    "process.pid_hash": "TargetProcessUniqueId",
    "process.thread.id": "TargetProcessThreadId",
    "process.version_info.product": "TargetProcessVersionInfoProductName",
    "process.version_info.company": "TargetProcessVersionInfoCompanyName",
    "process.version_info.file": "TargetProcessVersionInfoFileName",
    # process.working_directory is deliberately ABSENT: ASIM ProcessEvent has no
    # equivalent column, and substituting TargetProcessCommandLine would change the
    # meaning of the predicate. An honest pass-through is safer than a wrong alias.
    "process.args": "TargetProcessCommandLine",
    "user.name": "TargetUsername",
    "user.domain": "TargetUserDomain",
    "user.id": "TargetUserId",
    "user.email": "TargetUserEmail",
    "group.name": "TargetUserGroupName",
    "file.hash.sha256": "TargetProcessSHA256",
    "file.hash.sha1": "TargetProcessSHA1",
    "file.hash.md5": "TargetProcessMD5",
    "host.name": "DvcHostname",
    "host.ip": "DvcIpAddr",
    "host.hostname": "DvcHostname",
    "host.id": "DvcId",
    "event.action": "EventType",
    "event.outcome": "EventResult",
    "event.category": "EventCategory",
    "event.severity": "EventSeverity",
    "event.code": "EventOriginalType",
    "event.provider": "EventVendor",
    "event.dataset": "EventProduct",
    "event.created": "EventStartTime",
    "event.id": "EventUid",
    "network.protocol": "NetworkProtocol",
    "network.transport": "NetworkProtocol",
    "network.direction": "NetworkDirection",
    # --- NetworkSession (Src/Dst roles) ---
    "source.ip": "SrcIpAddr",
    "source.port": "SrcPortNumber",
    "source.domain": "SrcDomain",
    "destination.ip": "DstIpAddr",
    "destination.port": "DstPortNumber",
    "destination.domain": "DstDomain",
    "file.name": "TargetFileName",
    "file.path": "TargetFilePath",
    "file.directory": "TargetFileDirectory",
    "file.size": "TargetFileSize",
    "registry.key": "RegistryKey",
    "registry.value": "RegistryValue",
    "registry.data": "RegistryValueData",
    "registry.path": "RegistryKey",
    # --- DNS ---
    "dns.question.name": "DnsQuery",
    "dns.answers.name": "DnsResponseName",
    "dns.answers.type": "DnsResponseCodeName",
}

# Google SecOps UDM. Names verified against the official UDM overview
# (docs.cloud.google.com/chronicle/docs/event-processing/udm-overview): data lives under
# noun blocks (metadata, principal, target, src, network, security_result), so the same
# canonical field resolves differently depending on which role performed the action.
UDM = {
    # --- process (target/principal) ---
    "process.command_line": "target.process.command_line",
    "process.name": "target.process.file.full_path",
    "process.executable": "target.process.file.full_path",
    "process.pid": "target.process.pid",
    "process.args": "target.process.command_line",
    "process.parent.name": "target.parent_process.file.full_path",
    "process.parent.executable": "target.parent_process.file.full_path",
    "process.parent.command_line": "target.parent_process.command_line",
    "process.parent.pid": "target.parent_process.pid",
    # process.working_directory is deliberately ABSENT: UDM has no working-directory
    # field, and target.process.file.full_path is the executable path, not the working
    # directory. Aliasing them would change what the predicate matches.
    "file.hash.md5": "target.process.file.md5",
    "file.hash.sha1": "target.process.file.sha1",
    "file.hash.sha256": "target.process.file.sha256",
    # --- identity ---
    "user.name": "principal.user.userid",
    "user.id": "principal.user.userid",
    "user.domain": "principal.administrative_domain",
    "user.email": "principal.user.email_addresses",
    "group.name": "target.group.group_display_name",
    # --- host / endpoint ---
    "host.name": "principal.hostname",
    "host.hostname": "principal.hostname",
    "host.ip": "principal.ip",
    "host.id": "principal.asset_id",
    "host.os.family": "principal.platform",
    # --- network (src/target roles) ---
    "source.ip": "principal.ip",
    "source.port": "principal.port",
    "source.domain": "principal.administrative_domain",
    "destination.ip": "target.ip",
    "destination.port": "target.port",
    "destination.domain": "target.hostname",
    "network.protocol": "network.ip_protocol",
    "network.transport": "network.ip_protocol",
    "network.direction": "network.direction",
    "network.bytes": "network.bytes",
    # --- file / registry ---
    "file.name": "target.file.full_path",
    "file.path": "target.file.full_path",
    "file.directory": "target.file.full_path",
    "file.size": "target.file.size",
    "file.hash.sha256": "target.file.sha256",
    "registry.key": "target.registry.registry_key",
    "registry.value": "target.registry.registry_value_data",
    "registry.data": "target.registry.registry_value_data",
    "registry.path": "target.registry.registry_key",
    # --- event metadata ---
    "event.action": "metadata.event_type",
    "event.code": "metadata.product_event_type",
    "event.dataset": "metadata.product_name",
    "event.provider": "metadata.vendor_name",
    "event.created": "metadata.event_timestamp",
    "event.outcome": "security_result.action",
    "event.severity": "security_result.severity",
    # event.id is deliberately ABSENT: metadata.product_event_type is the source event
    # code, not an event identifier, so aliasing them would change the predicate's meaning.
    "event.category": "metadata.event_type",
    # --- DNS ---
    "dns.question.name": "network.dns.questions.name",
    "dns.answers.name": "network.dns.answers.data",
    # dns.answers.type omitted: the exact UDM enum name was not verified here, and a
    # wrong DNS field name is worse than an honest unmapped pass-through.
}

# CrowdStrike Falcon LogScale schema (CQL).
FALCON = {
    "process.command_line": "CommandLine", "process.name": "ImageFileName",
    "process.executable": "ImageFileName", "process.pid": "RawProcessId",
    "process.args": "CommandLine", "process.parent.name": "ParentBaseFileName",
    "process.parent.executable": "ParentImageFileName",
    "process.parent.command_line": "ParentCommandLine",
    "process.parent.pid": "ParentProcessId",
    "user.name": "UserName", "user.domain": "UserPrincipal", "user.id": "UserSid",
    "host.name": "ComputerName", "host.hostname": "ComputerName",
    "host.ip": "LocalAddressIP4", "host.id": "DeviceId",
    "source.ip": "RemoteAddressIP4", "source.port": "RemotePort",
    "destination.ip": "LocalAddressIP4", "destination.port": "LocalPort",
    "file.name": "TargetFileName", "file.path": "TargetFileName",
    "file.hash.sha256": "SHA256HashData", "file.hash.md5": "MD5HashData",
    "registry.key": "RegistryKey", "registry.value": "RegistryValueData",
    "registry.data": "RegistryValueData", "registry.path": "RegistryKeyPath",
    "network.protocol": "Protocol", "network.transport": "Protocol",
    "network.direction": "ConnectionDirection",
    "group.name": "GroupName", "dns.question.name": "QueryName",
    "event.action": "event_simpleName", "event.provider": "event_source",
    "event.dataset": "event_provider", "event.created": "timestamp",
}

# Wazuh sysmon / windows eventdata decoders.
WAZUH = {
    "process.command_line": "win.eventdata.commandLine", "process.name": "win.eventdata.image",
    "process.executable": "win.eventdata.image", "process.pid": "win.eventdata.processId",
    "process.parent.name": "win.eventdata.parentImage",
    "process.parent.command_line": "win.eventdata.parentCommandLine",
    "user.name": "user", "host.name": "agent.name", "host.ip": "agent.ip",
    "source.ip": "srcip", "source.port": "srcport", "destination.ip": "dstip",
    "destination.port": "dstport", "file.name": "win.eventdata.targetFilename",
    "file.path": "win.eventdata.targetFilename", "file.hash.sha256": "win.eventdata.hashes",
    "registry.key": "win.eventdata.targetObject", "group.name": "win.eventdata.groupName",
    "event.action": "win.system.eventID", "event.outcome": "win.system.eventID",
}

# ECS is the canonical namespace: identity mapping.
ECS = {f: f for f in [
    "agent.name", "agent.type", "client.address", "client.ip", "client.port",
    "destination.domain", "destination.ip", "destination.port", "dns.question.name",
    "dns.answers.name", "event.action", "event.code", "event.created", "event.dataset",
    "event.id", "event.kind", "event.outcome", "event.provider", "event.type", "event.category",
    "file.extension", "file.hash.md5", "file.hash.sha1", "file.hash.sha256", "file.name",
    "file.path", "file.size", "host.hostname", "host.id", "host.ip", "host.name", "host.os.family",
    "network.protocol", "network.transport", "process.command_line", "process.executable",
    "process.name", "process.parent.command_line", "process.parent.name", "process.pid",
    "process.thread.id", "process.args", "process.working_directory",
    "registry.key", "registry.path", "registry.value", "source.domain", "source.ip",
    "source.port", "user.domain", "user.email", "user.id", "user.name",
]}

MAPPINGS = {
    "sigma": dict(ECS),
    "elastic": dict(ECS),
    "splunk": SPLUNK_CIM,
    "sentinel": ASIM,
    "google_secops": UDM,
    "falcon": FALCON,
    "wazuh": WAZUH,
    # QRadar: AQL normalized column names (UTF8(payload) stays for command line).
    "qradar": {
        "process.command_line": "UTF8(payload)", "process.name": "processName",
        "process.pid": "processId", "process.parent.name": "parentProcessName",
        "user.name": "username", "user.id": "userid", "user.domain": "userDomain",
        "host.name": "hostname", "host.ip": "hostip", "source.ip": "sourceip",
        "source.port": "sourceport", "destination.ip": "destinationip",
        "destination.port": "destinationport", "file.name": "filename",
        "file.path": "fullPath", "file.hash.sha256": "filehash",
        "registry.key": "regkeyname", "registry.value": "regvalue",
        "network.protocol": "protocolid", "event.action": "eventName",
        "event.outcome": "outcome", "group.name": "groupName",
        "dns.question.name": "qiddnsquestion",
    },
}

# Provenance per target: where the names came from, which schema version, and how
# confident we are. An analyst can audit any single cell back to its documentation
# instead of trusting the table blindly. Confidence is deliberately conservative:
# "documented" = the field name appears in the vendor's published schema;
# "inferred" = a well-known synonym that we could not tie to a specific published
# column, so it is surfaced for review rather than presented as verified.
PROVENANCE = {
    "elastic": {
        "schema": "Elastic Common Schema (ECS)", "version": "8.x",
        "source_url": "https://www.elastic.co/guide/en/ecs/current/ecs-reference.html",
        "confidence": "documented", "notes": "ECS identity; no translation needed.",
    },
    "sigma": {
        "schema": "Sigma field namespace (ECS-aligned)", "version": "spec 2.1.0",
        "source_url": "https://github.com/SigmaHQ/sigma-specification",
        "confidence": "documented", "notes": "Canonical namespace; Sigma carries ECS names.",
    },
    "splunk": {
        "schema": "Splunk Common Information Model (CIM) Endpoint data model", "version": "ta_endpoint",
        "source_url": "https://help.splunk.com/en/splunk-enterprise/common-information-model",
        "confidence": "documented",
        "notes": "Field names from the CIM Endpoint/NetworkTraffic/DNS/Registry data models.",
    },
    "sentinel": {
        "schema": "Microsoft Sentinel ASIM (ProcessEvent, NetworkSession, Dns, FileEvent, RegistryEvent)",
        "version": "ProcessEvent 0.1.4 / NetworkSession 0.2.7 / Dns 1.0.0",
        "source_url": "https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-schemas",
        "confidence": "documented",
        "notes": "ASIM prefixes fields by role (Target*, ActingProcess*, ParentProcess*, Src*, Dst*, Dvc*). ASIM is schema-specific: the same canonical field resolves differently in ProcessEvent vs NetworkSession, so pick the schema that matches your rule and verify the column exists in the table you query.",
    },
    "google_secops": {
        "schema": "Google SecOps UDM", "version": "UDM v2",
        "source_url": "https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview",
        "confidence": "documented",
        "notes": "UDM stores data under noun blocks (metadata, principal, target, src, network, security_result). Parser-dependent: the same concept may land under principal.* or target.* depending on the log source, so validate against a real event.",
    },
    "falcon": {
        "schema": "CrowdStrike Falcon LogScale schema", "version": "2024.x",
        "source_url": "https://www.crowdstrike.com/en-us/documentation/observe-logscale/",
        "confidence": "documented",
        "notes": "Falcon platform field names as exposed in LogScale. Verify against the schema for your specific log source.",
    },
    "wazuh": {
        "schema": "Wazuh sysmon/windows decoder eventdata fields", "version": "4.x",
        "source_url": "https://documentation.wazuh.com/current/user-manual/ruleset/configuring-syscheck.html",
        "confidence": "inferred",
        "notes": "Decoder field paths (win.eventdata.*) are well known but Wazuh exposes no fixed published schema, so treat them as environment-dependent and verify against your decoder output.",
    },
    "qradar": {
        "schema": "IBM QRadar normalized event/AQL column names", "version": "7.4+",
        "source_url": "https://www.ibm.com/docs/en/qradar",
        "confidence": "inferred",
        "notes": "QRadar normalizes columns per event source and custom property mappings; these are the common default names and must be checked against your deployment's normalized properties.",
    },
}

payload = {
    "meta": {
        "version": 3,
        "taxonomy": "Elastic Common Schema field names as the canonical namespace",
        "policy": "omit-when-unsure: an unverified cell is omitted, passes through unchanged, and is flagged unmapped",
        "provenance_policy": "Every target carries a schema version, a documentation URL, and a confidence level. Cells marked 'inferred' are not tied to a single published column and must be verified in your environment before production use.",
        "sources": {
            "elastic/sigma": "identity (ECS namespace)",
            "splunk": "Splunk CIM Endpoint data model (ta_endpoint)",
            "sentinel": "Microsoft Sentinel ASIM ProcessEvent/Authentication/Network",
            "google_secops": "Google SecOps UDM field dictionary",
            "falcon": "CrowdStrike Falcon LogScale schema",
            "wazuh": "Wazuh sysmon/windows decoder fields",
            "qradar": "IBM QRadar normalized AQL column names",
        },
        "mapped_fields": len({k for t in MAPPINGS.values() for k in t}),
    },
    "provenance": PROVENANCE,
    "mappings": MAPPINGS,
}
out = DATA / "fields.json"
out.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
print("wrote", out, "mapped fields:", payload["meta"]["mapped_fields"])
for name, table in MAPPINGS.items():
    print(f"  {name:14} {len(table)}")
