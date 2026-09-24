# RuleForge — Multi-SIEM Rule Generator

RuleForge creates review-ready detection-rule starting points in Sigma YAML and native query languages for Splunk Enterprise Security (SPL), Microsoft Sentinel (KQL), Elastic Security (EQL), IBM QRadar (AQL), Google SecOps (YARA-L 2.0), CrowdStrike Falcon LogScale (CQL), and Wazuh (Ruleset XML).

## Workbench capabilities

- Native-field mappings for common canonical fields such as `process.command_line`, `user.name`, `host.name`, and source/destination IPs.
- Sigma as a vendor-neutral detection layer with metadata, logsource, detection selections, conditions, filters, tags, and false-positive context.
- Explicit import fidelity (`exact`, `partial`, or `unsupported`) and compile contracts so a normalized draft is never presented as an equivalent native rule.
- Structured preservation of event sequences, joins, aggregations, lookups, native sections, and Wazuh XML correlation metadata.
- Quality gates that flag broad data sources, unmapped custom fields, and potential single-event noise before a rule is saved.
- A persistent local SQLite history of every generated and analyzed rule.
- Reproducible JSON rule packages containing the rule definition, quality-gate findings, mappings, and every rendered SIEM artifact.

This is a local detection-engineering workbench. It intentionally does **not** connect to SIEMs or deploy changes. A true multi-user enterprise deployment still requires SSO/RBAC, an audited managed database, a secrets manager, CI validation against vendor APIs, and approved deployment pipelines.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Then visit `http://127.0.0.1:5000`.

## Important usage note

The tool produces normalized-field templates, not production-approved rules. Map fields to your telemetry schema, confirm required log sources and event IDs, test with representative data, tune allowlists, and follow your organization’s change-control process before enabling an alert.

## Verification status — read this before trusting an output

Be precise about what "validated" means here, because the difference matters when a rule silently never fires.

**What is actually verified**

- Generated SPL, KQL, EQL, AQL, CQL, YARA-L, Wazuh XML, and Sigma are passed through structural parsers that check clause order, delimiters, balanced expressions, and required sections. A `validated: structure-parsed` tag means that check passed.
- When `pySigma` and a matching backend package are installed, genuine Sigma YAML is converted by the **vendor-authored backend** and tagged authoritative.
- A cross-product render sweep compiles every catalogued pattern against every target.

**What is NOT verified**

- **No live SIEM.** No rule here has been executed against a running Splunk, Sentinel, Elastic, QRadar, SecOps, Falcon, or Wazuh instance. A structural parse cannot tell you that a column exists, that a table is joined, or that your data source name is right.
- **Wazuh and QRadar field names are inferred.** Neither publishes a fixed field schema, so those mappings are conventions, not verified columns. They are labelled `inferred` in the UI for this reason.
- **Advanced constructs are mostly not portable.** EQL is the only supported target with a native sequence operator. For `sequence`, `join`, `aggregation`, and `absence`, the other targets receive a labelled `partial` projection or an explicit "rebuild this by hand" note. Treat a `partial` output as a drafting aid, not an equivalent rule.
- **A pass in CI is not a live-engine result.** The test suite proves internal consistency and grammar conformance. It cannot prove a rule fires in your environment.

Field translations are drawn from published schemas where they exist. See [Mappings and their sources](docs/readiness-assessment.md) for per-target provenance.

## References used for the design

- [Splunk correlation search overview](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.3/correlation-searches/correlation-search-overview-for-splunk-enterprise-security) — SPL searches can aggregate data and drive adaptive response actions.
- [Microsoft Sentinel scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) and [rule-as-code schema](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-analytic-rules-creation) — KQL queries, lookback periods, thresholds, and MITRE mappings inform the Sentinel template.
- [Elastic EQL rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/eql) — event categories and ordered correlation; threshold rules are deliberately identified for aggregation use cases.
- [IBM QRadar AQL examples](https://www.ibm.com/docs/en/qradar-on-cloud?topic=searches-advanced-search-options) — AQL `SELECT`, `WHERE`, and `GROUP BY` structure.
- [Google SecOps YARA-L 2.0 introduction](https://docs.cloud.google.com/chronicle/docs/yara-l/getting-started) — required rule sections, UDM, grouping, and outcomes.
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) and [Ruleset XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) — custom ID range, XML rule elements, frequency/timeframe correlation, groups, and MITRE mappings.
- [Sigma rule specification](https://sigmahq.io/docs/basics/rules.html) and [pySigma](https://github.com/SigmaHQ/pySigma) — vendor-neutral metadata, logsource, detection selections, conditions, filters, pipelines, and separate backend conversion.

SIEM dialects, parsers, and data models vary by product version. Generated queries are intentionally transparent, editable starting points.

### Wazuh deployment workflow

The Wazuh output is a local custom-rule template. Choose an unused ID between `100000` and `120000`, map its `<field>` name to the field emitted by your installed decoder, and add an optional parent rule ID only when you are extending a confirmed existing rule. Save the reviewed XML under `/var/ossec/etc/rules/`, test it with `wazuh-logtest`, and restart the Wazuh manager only after it passes.
