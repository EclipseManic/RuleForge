"""The 70-cell expectation matrix: what each of the 10 rules may honestly become per target.

Phase 0 of docs/ruleforge-redesign-plan.md. Every one of the 70 cells is declared here, so
a vertical slice cannot be declared "done" while quietly leaving targets unhandled.

Three support values are permitted and there is no fourth:

    native      the target expresses it with its own construct
    equivalent  an exact composition of registered target capabilities, no semantic change
    refused     no faithful path -> EMPTY artifact plus a named refusal reason

A "partial" value that still produces a downloadable artifact does not exist, on purpose.
That is the defect class this redesign ends.

`refusal` is mandatory and specific whenever support is "refused": a refusal with no
reason is a bug, because the whole point is to tell the analyst what to build by hand.
"""

from tests.corpus.rule_corpus import RULES, TARGETS, rule_ids

# Per-target notes that apply across the whole corpus.
GLOBAL_TARGET_NOTES = {
    "wazuh": "no fixed time buckets, no multi-measure aggregation, only linear if_sid "
             "chains with a single sliding if_matched_sid counter; always inferred_target",
    "qradar": "field names are inferred; AQL cannot express a stateful sequence, which "
              "requires the Custom Rules Engine",
    "elastic": "ES|QL has no event-stream sequence; EQL covers a restricted linear subset; "
               "LOOKUP JOIN is enrichment, not temporal event correlation",
    "sigma": "not a target: Sigma is an interchange format with no execution semantics",
}

# The authoritative matrix. Key is (rule_id, target).
# Values: (support, refusal_code, note)
_MATRIX = {
    # ---- t1_splunk_lsass_network: filter -> aggregate -> filter on aggregate
    ("t1_splunk_lsass_network", "splunk"): ("native", None, "stats then where is native SPL"),
    ("t1_splunk_lsass_network", "sentinel"): ("native", None, "summarize then where is native KQL"),
    ("t1_splunk_lsass_network", "elastic"): ("native", None, "STATS BY then WHERE is native ES|QL"),
    ("t1_splunk_lsass_network", "qradar"): ("native", None, "GROUP BY then HAVING is native AQL"),
    ("t1_splunk_lsass_network", "google_secops"): ("native", None, "outcome variables plus a condition"),
    ("t1_splunk_lsass_network", "falcon"): ("native", None, "groupBy then test is native CQL"),
    ("t1_splunk_lsass_network", "wazuh"): (
        "refused", "WAZUH_NO_AGGREGATE_FILTER",
        "Wazuh has no construct equivalent to filter on an aggregate result; rebuild natively"),

    # ---- t1_sentinel_impossible_travel: two named measures + bin
    ("t1_sentinel_impossible_travel", "sentinel"): ("native", None, "countif and bin are native KQL"),
    ("t1_sentinel_impossible_travel", "splunk"): ("equivalent", None,
                                                  "named measures lower to stats with sum(if(...)) and bin"),
    ("t1_sentinel_impossible_travel", "elastic"): ("native", None,
                                                   "per-expression STATS WHERE plus BUCKET"),
    ("t1_sentinel_impossible_travel", "google_secops"): ("native", None,
                                                         "outcome variables plus condition"),
    ("t1_sentinel_impossible_travel", "falcon"): ("native", None, "groupBy plus test"),
    ("t1_sentinel_impossible_travel", "qradar"): (
        "refused", "QRADAR_COMPUTED_BUCKET_UNSUPPORTED",
        "AQL LAST is scan scope, not a computed tumbling bucket; no faithful fixed bucket"),
    ("t1_sentinel_impossible_travel", "wazuh"): (
        "refused", "WAZUH_NO_NAMED_MEASURES",
        "Wazuh rules expose no multiple named measures in one rule"),

    # ---- t1_wazuh_powershell_chain: ordered stages, shared window
    ("t1_wazuh_powershell_chain", "wazuh"): ("native", None,
                                              "parent/child if_sid chain, the target's own construct"),
    ("t1_wazuh_powershell_chain", "elastic"): ("refused", "EQL_OUT_OF_SCOPE_FOR_ESQL",
                                               "sequence is EQL, a separate dialect; not a lossy ES|QL projection"),
    ("t1_wazuh_powershell_chain", "sentinel"): ("refused", "SENTINEL_NO_NATIVE_SEQUENCE",
                                                 "KQL has no native streaming sequence operator"),
    ("t1_wazuh_powershell_chain", "splunk"): ("refused", "SPL_SEQUENCE_NOT_NATIVE",
                                              "transaction/streamstats do not express ordered stage windows faithfully"),
    ("t1_wazuh_powershell_chain", "qradar"): ("native", None,
                                              "QRadar CRE event_sequence is the native construct"),
    ("t1_wazuh_powershell_chain", "google_secops"): ("native", None, "ordered event variables over a match window"),
    ("t1_wazuh_powershell_chain", "falcon"): ("native", None, "correlate sequence=true within="),

    # ---- t1_qradar_brute_force_success: stateful WHEN/FOLLOWED BY
    ("t1_qradar_brute_force_success", "qradar"): ("native", None, "CRE event_sequence with a test stack"),
    ("t1_qradar_brute_force_success", "wazuh"): (
        "refused", "WAZUH_NO_BRANCHING_STATE_MACHINE",
        "Wazuh requires success AND privileged within one shared post-failure window, which "
        "its if_sid chain and single sliding counter cannot express"),
    ("t1_qradar_brute_force_success", "sentinel"): (
        "refused", "SENTINEL_NO_NATIVE_STATE_MACHINE",
        "KQL has no state machine; a scheduled self-join is a different rule and is not offered"),
    ("t1_qradar_brute_force_success", "splunk"): (
        "refused", "SPL_NO_STATEFUL_THRESHOLD_COUNTER",
        "SPL transaction cannot express a counted threshold followed by two terminal conditions"),
    ("t1_qradar_brute_force_success", "elastic"): (
        "refused", "EQL_NO_COUNTER_SEQUENCE",
        "EQL sequence is ordered-stage only, not a counted threshold with terminal conditions"),
    ("t1_qradar_brute_force_success", "google_secops"): (
        "refused", "YARAL_NO_COUNTERED_SEQUENCE",
        "YARA-L matches event variables; a counted threshold with terminal conditions is not expressible"),
    ("t1_qradar_brute_force_success", "falcon"): (
        "refused", "CQL_NO_BRANCHING_SEQUENCE",
        "CQL correlate sequence=true is linear; a branching counted state machine is not expressible"),

    # ---- t1_yaral_process_conn: two streams + outcome
    ("t1_yaral_process_conn", "google_secops"): ("native", None, "the rule's own dialect"),
    ("t1_yaral_process_conn", "splunk"): ("native", None, "inner temporal join plus eval risk"),
    ("t1_yaral_process_conn", "sentinel"): ("native", None, "join with a time-key relation plus extend"),
    ("t1_yaral_process_conn", "falcon"): ("native", None, "correlate subqueries with connections and within"),
    ("t1_yaral_process_conn", "elastic"): (
        "refused", "LOOKUP_JOIN_IS_ENRICHMENT_NOT_CORRELATION",
        "ES|QL LOOKUP JOIN enriches; it is not temporal event-stream correlation"),
    ("t1_yaral_process_conn", "qradar"): (
        "refused", "QRADAR_NO_ARBITRARY_TEMPORAL_JOIN",
        "AQL subquery projection is not a temporal multi-stream join"),
    ("t1_yaral_process_conn", "wazuh"): (
        "refused", "WAZUH_NO_MULTI_STREAM_JOIN",
        "Wazuh same_* is restricted prior-event correlation, not a general multi-stream join"),

    # ---- t2_wazuh_rule_bundle: a PACKAGE with a dependency edge
    ("t2_wazuh_rule_bundle", "wazuh"): (
        "native", None,
        "two-rule package; standalone deployment is separately refused while sysmon_event_10 "
        "is an unresolved external dependency"),
    ("t2_wazuh_rule_bundle", "splunk"): (
        "refused", "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE",
        "a package with a rule-alert dependency edge is Wazuh's correlator model"),
    ("t2_wazuh_rule_bundle", "sentinel"): (
        "refused", "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE", "same"),
    ("t2_wazuh_rule_bundle", "elastic"): (
        "refused", "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE", "same"),
    ("t2_wazuh_rule_bundle", "qradar"): (
        "refused", "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE", "same"),
    ("t2_wazuh_rule_bundle", "google_secops"): (
        "refused", "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE", "same"),
    ("t2_wazuh_rule_bundle", "falcon"): (
        "refused", "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE", "same"),

    # ---- t2_splunk_tstats_subquery: accelerated summary + non-temporal join
    ("t2_splunk_tstats_subquery", "splunk"): ("native", None,
                                               "tstats, subquery defaults and non-temporal join are native SPL"),
    ("t2_splunk_tstats_subquery", "sentinel"): (
        "refused", "ACCELERATED_SUMMARY_UNAVAILABLE",
        "no equivalent of summariesonly over a datamodel; raw events would change completeness and latency"),
    ("t2_splunk_tstats_subquery", "elastic"): (
        "refused", "ACCELERATED_SUMMARY_UNAVAILABLE", "same"),
    ("t2_splunk_tstats_subquery", "qradar"): (
        "refused", "ACCELERATED_SUMMARY_UNAVAILABLE", "same"),
    ("t2_splunk_tstats_subquery", "google_secops"): (
        "refused", "ACCELERATED_SUMMARY_UNAVAILABLE", "same"),
    ("t2_splunk_tstats_subquery", "falcon"): (
        "refused", "ACCELERATED_SUMMARY_UNAVAILABLE", "same"),
    ("t2_splunk_tstats_subquery", "wazuh"): (
        "refused", "ACCELERATED_SUMMARY_UNAVAILABLE", "same"),

    # ---- t2_sentinel_temporal_join: equijoin + asymmetric temporal predicate
    ("t2_sentinel_temporal_join", "sentinel"): ("native", None, "the rule's own dialect"),
    ("t2_sentinel_temporal_join", "splunk"): ("native", None,
                                               "equijoin plus an explicit inclusive time-key predicate"),
    ("t2_sentinel_temporal_join", "google_secops"): ("native", None,
                                                      "event variables sharing a match key over a window"),
    ("t2_sentinel_temporal_join", "falcon"): ("native", None, "correlate connections with within"),
    ("t2_sentinel_temporal_join", "elastic"): (
        "refused", "ESQL_NO_TEMPORAL_EVENT_JOIN",
        "ES|QL LOOKUP JOIN is enrichment, not a temporal join over two event streams"),
    ("t2_sentinel_temporal_join", "qradar"): (
        "refused", "AQL_NO_TEMPORAL_EVENT_JOIN", "AQL has no temporal multi-stream join"),
    ("t2_sentinel_temporal_join", "wazuh"): (
        "refused", "WAZUH_NO_JOINED_ROW_AGGREGATION",
        "Wazuh cannot express a two-stream join, a joined-row count, or make_set output"),

    # ---- t2_qradar_grouped_aql: grouped HISTORICAL search
    ("t2_qradar_grouped_aql", "qradar"): (
        "native", None,
        "emitted as qr_aql_saved_search with is_event_sequence=false; a detecting rule is "
        "separately refused with QRADAR_CRE_CUSTOM_RULE_REQUIRED, and the absent time range "
        "is never invented"),
    ("t2_qradar_grouped_aql", "splunk"): ("equivalent", None, "grouped filter, count, HAVING and sort are native SPL"),
    ("t2_qradar_grouped_aql", "sentinel"): ("native", None, "summarize then where"),
    ("t2_qradar_grouped_aql", "elastic"): ("native", None, "STATS BY then WHERE"),
    ("t2_qradar_grouped_aql", "google_secops"): ("native", None, "outcome variables plus condition"),
    ("t2_qradar_grouped_aql", "falcon"): ("native", None, "groupBy plus test"),
    ("t2_qradar_grouped_aql", "wazuh"): (
        "refused", "WAZUH_NO_AGGREGATE_FILTER",
        "Wazuh has no post-aggregate filter construct"),

    # ---- t2_yaral_cross_event: cross-event comparison
    ("t2_yaral_cross_event", "google_secops"): (
        "native", None,
        "the supplied source is refused with YARAL_META_SOURCE_INVALID_OR_UNRESOLVED because "
        "its meta block is not valid syntax; the semantic core remains modelable once the "
        "analyst supplies valid metadata"),
    ("t2_yaral_cross_event", "splunk"): (
        "refused", "SPL_NO_CROSS_EVENT_COMPARISON",
        "SPL compares within a row, not across two correlated events"),
    ("t2_yaral_cross_event", "sentinel"): (
        "refused", "KQL_NO_CROSS_EVENT_COMPARISON",
        "the comparison is resolvable only after a join, which changes the rule's shape"),
    ("t2_yaral_cross_event", "elastic"): (
        "refused", "ESQL_NO_CROSS_EVENT_COMPARISON", "same"),
    ("t2_yaral_cross_event", "qradar"): (
        "refused", "AQL_NO_CROSS_EVENT_COMPARISON", "same"),
    ("t2_yaral_cross_event", "falcon"): (
        "refused", "CQL_NO_CROSS_EVENT_COMPARISON", "same"),
    ("t2_yaral_cross_event", "wazuh"): (
        "refused", "WAZUH_NO_CROSS_EVENT_COMPARISON", "same"),
}

SUPPORT_VALUES = {"native", "equivalent", "refused"}


def expect(rule_id, target):
    """Declared expectation for one matrix cell. KeyError if a cell is undeclared."""
    if rule_id not in RULES:
        raise KeyError(f"unknown rule {rule_id!r}")
    if target not in TARGETS:
        raise KeyError(f"unknown target {target!r}")
    try:
        return _MATRIX[(rule_id, target)]
    except KeyError:
        raise KeyError(
            f"matrix cell ({rule_id}, {target}) is undeclared - every one of the "
            f"{len(rule_ids()) * len(TARGETS)} cells must be stated explicitly") from None


def all_cells():
    return [(rid, target, expect(rid, target)) for rid in rule_ids() for target in TARGETS]


def declared_cell_count():
    return len(_MATRIX)


def undeclared_cells():
    return [(r, t) for r in rule_ids() for t in TARGETS if (r, t) not in _MATRIX]


def extra_cells():
    """Declared cells that refer to a rule or target outside the corpus."""
    return sorted(cell for cell in _MATRIX if cell[0] not in RULES or cell[1] not in TARGETS)
