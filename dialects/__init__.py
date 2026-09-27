"""Dialect front-ends: native syntax in, neutral IR out, and back.

Each dialect is three things and no more:

    parse    native text -> parsed structure
    lower    parsed structure -> RuleIR
    render   RuleIR -> native text

Plus diagnostics, which are first-class rather than log noise. A warning here
means "this is valid and will run, but here is what it actually means", and it is
the difference between a tool that reformats text and one that helps.
"""

from __future__ import annotations

from dialects.aql import DIALECT as AQL_DIALECT
from dialects.aql import LANGUAGE as AQL_LANGUAGE
from dialects.aql import Diagnostic
from dialects.aql import parse_aql
from dialects.aql_ir import cre_from_ir, lower as lower_aql, render as render_aql
from dialects.kql import DIALECT as KQL_DIALECT
from dialects.kql import LANGUAGE as KQL_LANGUAGE
from dialects.kql import parse_kql
from dialects.kql_ir import lower as lower_kql
from dialects.yaral import DIALECT as YARAL_DIALECT
from dialects.yaral import LANGUAGE as YARAL_LANGUAGE
from dialects.yaral import parse_yaral
from dialects.yaral_ir import lower as lower_yaral, render as render_yaral
from dialects.spl import DIALECT as SPL_DIALECT
from dialects.spl import LANGUAGE as SPL_LANGUAGE
from dialects.spl import parse_spl
from dialects.spl_ir import lower as lower_spl
from dialects.spl_render import render as render_spl
from dialects.eql import DIALECT as EQL_DIALECT
from dialects.eql import LANGUAGE as EQL_LANGUAGE
from dialects.eql import parse_eql
from dialects.eql_ir import lower as lower_eql
from dialects.eql_render import render as render_eql
from dialects.fql import DIALECT as FQL_DIALECT
from dialects.fql import LANGUAGE as FQL_LANGUAGE
from dialects.fql import parse_fql
from dialects.fql_ir import MAX_PROPERTIES as FQL_MAX_PROPERTIES
from dialects.fql_ir import lower as lower_fql
from dialects.fql_render import render as render_fql
from dialects.wazuh import DIALECT as WAZUH_DIALECT
from dialects.wazuh import LANGUAGE as WAZUH_LANGUAGE
from dialects.wazuh import parse_wazuh
from dialects.wazuh_ir import lower as lower_wazuh
from dialects.wazuh_render import render as render_wazuh
from dialects.kql_render import render as render_kql

__all__ = [
    "Diagnostic",
    "parse_aql", "lower_aql", "render_aql", "cre_from_ir",
    "AQL_DIALECT", "AQL_LANGUAGE",
    "parse_yaral", "lower_yaral", "render_yaral",
    "YARAL_DIALECT", "YARAL_LANGUAGE",
    "parse_kql", "lower_kql", "render_kql",
    "KQL_DIALECT", "KQL_LANGUAGE",
    "parse_wazuh", "lower_wazuh", "render_wazuh",
    "WAZUH_DIALECT", "WAZUH_LANGUAGE",
    "parse_spl", "lower_spl", "render_spl",
    "SPL_DIALECT", "SPL_LANGUAGE",
    "parse_eql", "lower_eql", "render_eql",
    "EQL_DIALECT", "EQL_LANGUAGE",
    "parse_fql", "lower_fql", "render_fql",
    "FQL_DIALECT", "FQL_LANGUAGE", "FQL_MAX_PROPERTIES",
    "TARGETS",
]

#: The platforms this tool targets. Names only -- this table records WHICH
#: syntaxes must be handled, not where code for them lives.
TARGETS: dict[str, str] = {
    "yaral": "YARA-L 2.0",
    "qradar": "AQL",
    "sentinel": "KQL",
    "wazuh": "Ruleset XML",
    "splunk": "SPL",
    "elastic": "EQL",
    "falcon": "CQL",
    "sigma": "Sigma YAML",
}
