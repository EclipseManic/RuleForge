"""Expand data/techniques.json buildable templates using the real ATT&CK catalog.

The curated quick-starts stay untouched. For every other ATT&CK technique we can classify
with confidence (event category, tactic, a sensible default field/value), we emit a real
buildable template. Techniques we cannot classify are left reference-only in
data/attack_catalog.json rather than given a fake default - a wrong default field produces
a rule that silently never matches, which is worse than no template.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

TECHNIQUES_PATH = DATA / "techniques.json"
ATTACK_PATH = DATA / "attack_catalog.json"
out_path = DATA / "techniques.json"

doc = json.loads(TECHNIQUES_PATH.read_text(encoding="utf-8"))
attack = json.loads(ATTACK_PATH.read_text(encoding="utf-8"))["techniques"]
existing = doc["techniques"]
covered = {tid for entry in existing.values() for tid in entry.get("mitre", [])}

# Category inference: ordered rules, first match wins. Each pattern maps an ATT&CK technique
# name to the event category plus the canonical field/value an analyst would start from.
RULES: list[tuple[str, str, str, str, str]] = [
    # (regex, label override or "", event_category, default_field, default_value)
    (r"credential\s+dump|lsass|mimikatz|ntds|vault", "", "process", "process.command_line", "*"),
    (r"pass.?the.?hash|psexec|wmi|remote\s+service|smb.*admin|rdp|lateral", "", "network", "destination.port", "*"),
    (r"brute|password|spray|authentication", "", "authentication", "user.name", "*"),
    (r"scheduled\s+task|cron|at\s+root|systemd|launchd|startup|run\s+key|boot.*exec", "", "file", "file.path", "*"),
    (r"registry|run\s+key|startup|persistence", "", "registry", "registry.key", "*"),
    (r"web\s+shell|webshell|reverse\s+shell|command.*shell|powershell|cmd\.exe|scripting", "", "process", "process.command_line", "*"),
    (r"encode|obfuscat|compress|archive|packing|base64", "", "process", "process.command_line", "*"),
    (r"dns", "", "dns", "dns.question.name", "*"),
    (r"proxy|exfil|exfiltrat|archive|upload|cloud.*storage", "", "network", "destination.ip", "*"),
    (r"disable|defender|firewall|security\s+tool|tamper|audit.*log|clear.*log|indicator.*remov", "", "process", "process.command_line", "*"),
    (r"service\s+creat|system\s+service|wmi.*subscription", "", "process", "process.name", "*"),
    (r"discovery|recon|scan|whois|net.*view|systeminfo|arp|ipconfig|net1", "", "process", "process.command_line", "*"),
    (r"privilege|escalat|uac|bypass.*uac|sudo|setuid", "", "process", "process.command_line", "*"),
    (r"account|user\s+creat|group.*add|permission.*modif", "", "iam", "user.name", "*"),
    (r"cloud|iam.*anomal|oauth|api\s+key|access\s+key|token", "", "cloud", "user.name", "*"),
    (r"container|kubernetes|docker", "", "process", "process.name", "*"),
    (r"certificate|root\s+cert|trust\s+modif|trustlet", "", "registry", "registry.value", "*"),
    (r"input\s+capture|keylog|screenshot|clipboard", "", "process", "process.name", "*"),
    (r"video\s+capture|webcam", "", "process", "process.name", "*"),
    (r"data\s+from.*(local|remote)|local.*data|collection", "", "file", "file.path", "*"),
    (r"resource\s+develop|develop.*capab", "", "process", "process.command_line", "*"),
    (r"search.*(victim|internal|security)|search.*website|internal.*search", "", "process", "process.command_line", "*"),
    (r"network\s+sniff|packet\s+capture|wireshark|tcpdump", "", "network", "destination.ip", "*"),
    (r"modify.*(existing|registry)|change.*file|timestomp|artifact.*remov", "", "file", "file.path", "*"),
    (r"fallback|downgrade", "", "process", "process.command_line", "*"),
    (r"supply.?chain|compromise.*software|update.*malicious|backdoor.*software", "", "process", "process.name", "*"),
    (r"hijack|execution.*proxy|signed.*binary.*proxy|mshta|rundll32|regsvr32|cscript|wscript|msiexec", "", "process", "process.name", "*"),
    (r"inhibit.*(log|artifact|defense)|impair.*defense", "", "process", "process.command_line", "*"),
    (r"virtual.*machine|sandbox|system.*profil|defense.*evasion", "", "process", "process.name", "*"),
    (r"time.*skew|time.*change", "", "process", "process.command_line", "*"),
    (r"email|phish|spearphos|message|smtp", "", "network", "destination.ip", "*"),
    (r"web\s+protocol|http|proxy\s+comm", "", "network", "network.protocol", "*"),
    (r"software.*packing|compress.*data|compress.*content", "", "file", "file.extension", "*"),
    (r"office|macro|document.*content|attachment|email\s+content", "", "file", "file.name", "*"),
    (r"shared.*(code|module|object)|reflective.*load|inject", "", "process", "process.name", "*"),
    (r"boot|logon\s+autostart|image\s+load", "", "process", "process.name", "*"),
    (r"extra\s+window|window|desktop|hide", "", "process", "process.command_line", "*"),
    (r"email\s+forward|mail|forward", "", "network", "destination.ip", "*"),
    (r"chat|message\s+channel|telegram|discord", "", "network", "destination.ip", "*"),
    (r"broadcast|multicast", "", "network", "destination.ip", "*"),
    (r"drive|removable|usb|cdrom", "", "file", "file.path", "*"),
    (r"burp|proxy.*discover|network.*config", "", "network", "destination.ip", "*"),
    (r"reduce.*window|footprint|indicator\s+remov|artifact", "", "process", "process.command_line", "*"),
    (r"vlan|network.*boundary|firewall.*rule|acl", "", "network", "destination.ip", "*"),
    (r"trust.*establish|admine|domain.*trust", "", "iam", "user.name", "*"),
    (r"default.*account|default.*password|default.*credential", "", "iam", "user.name", "*"),
    (r"password.*policy|account.*lock|brute", "", "authentication", "user.name", "*"),
    (r"video|audio|capture", "", "process", "process.name", "*"),
    (r"system\s+owner|permission.*discovery|account\s+discovery", "", "iam", "user.name", "*"),
    (r"application\s+window|window.*discovery|desktop\s+session", "", "process", "process.name", "*"),
    (r"system\s+config|config.*discovery|firewall.*discover|security\s+software", "", "process", "process.name", "*"),
    (r"system\s+owner.*discover|local\s+account", "", "iam", "user.name", "*"),
    (r"permission.*discover", "", "iam", "user.name", "*"),
    # --- evidence-based coverage -------------------------------------------------
    # A template whose default value is "*" teaches the analyst nothing, so these
    # rules only fire for techniques that name a well-known binary or protocol. The
    # default is then a concrete, defensible starting point rather than a placeholder.
    (r"powershell|pwsh", "PowerShell Execution", "process", "process.name", "powershell.exe"),
    (r"wscript|cscript|javascript|vbscript|script\s+hosting", "Script Host Process", "process", "process.name", "cscript.exe"),
    (r"mshta", "Mshta Execution", "process", "process.name", "mshta.exe"),
    (r"rundll32", "Rundll32 Execution", "process", "process.name", "rundll32.exe"),
    (r"regsvr32", "Regsvr32 Execution", "process", "process.name", "regsvr32.exe"),
    (r"certutil", "Certutil Download", "process", "process.name", "certutil.exe"),
    (r"bitsadmin", "BITS Transfer", "process", "process.name", "bitsadmin.exe"),
    (r"wmic", "WMI Command Line", "process", "process.name", "wmic.exe"),
    (r"psexec|sysinternals", "PsExec Execution", "process", "process.name", "psexec.exe"),
    (r"mimikatz", "Mimikatz Credential Dumping", "process", "process.name", "mimikatz.exe"),
    (r"adfind|net\s*\.?\s*user|net\s+user|net\s+group|net\s+localgroup", "Account Enumeration", "process", "process.name", "net.exe"),
    (r"nslookup|\bdig\b", "DNS Resolution Activity", "process", "process.name", "nslookup.exe"),
    (r"whoami", "Account Discovery via whoami", "process", "process.name", "whoami.exe"),
    (r"systeminfo|msinfo32", "System Information Discovery", "process", "process.name", "systeminfo.exe"),
    (r"ipconfig|getmac|\barp\b", "Network Configuration Discovery", "process", "process.name", "ipconfig.exe"),
    (r"schtasks", "Scheduled Task Creation", "process", "process.name", "schtasks.exe"),
    (r"vssadmin|bcdedit|wbadmin", "Shadow Copy or Recovery Tampering", "process", "process.name", "vssadmin.exe"),
    (r"wevtutil", "Event Log Tampering", "process", "process.name", "wevtutil.exe"),
    (r"lsass", "LSASS Memory Access", "process", "process.executable", "lsass.exe"),
    (r"ntds|\bsam\b", "Credential File Access", "process", "process.command_line", "*"),
]

# Technique-name cleanup so slugs and labels are readable.
def slug(name: str, tid: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return (base or "technique")[:60] + f"_{tid.replace('.', '_').lower()}"


added = 0
skipped = 0
for tid, meta in attack.items():
    if tid in covered:
        continue
    name = meta.get("name", "")
    for pattern, label_override, category, field, value in RULES:
        if re.search(pattern, name, re.IGNORECASE):
            key = slug(name, tid)
            if key in existing:
                break
            existing[key] = {
                "label": label_override or name,
                "default_field": field,
                "default_value": value,
                "event_category": category,
                "event_filter": "",
                "mitre": [tid],
                "description": (meta.get("summary", "") or name)[:300],
                "tactic": (meta.get("tactics") or [""])[0],
                "fp_guidance": "",
            }
            added += 1
            break
    else:
        skipped += 1

doc["meta"] = {
    **doc.get("meta", {}),
    "version": 2,
    "note": "Quick-starts (curated) plus templates generated from the MITRE ATT&CK catalog for "
            "classifiable techniques. Unclassifiable techniques stay reference-only in "
            "data/attack_catalog.json and are marked buildable=false in the UI.",
    "generated_from_attack": True,
}
out_path.write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
print(f"templates: {len(existing)} (+{added} generated, {skipped} reference-only of {len(attack)} ATT&CK techniques)")
