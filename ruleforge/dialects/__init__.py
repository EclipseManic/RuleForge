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

from .aql import DIALECT as AQL_DIALECT
from .aql import LANGUAGE as AQL_LANGUAGE
from .aql import Diagnostic
from .aql import parse_aql
from .aql_ir import cre_from_ir, lower as lower_aql, render as render_aql
from .kql import DIALECT as KQL_DIALECT
from .kql import LANGUAGE as KQL_LANGUAGE
from .kql import parse_kql
from .kql_ir import lower as lower_kql
from .yaral import DIALECT as YARAL_DIALECT
from .yaral import LANGUAGE as YARAL_LANGUAGE
from .yaral import parse_yaral
from .yaral_ir import lower as lower_yaral, render as render_yaral
from .spl import DIALECT as SPL_DIALECT
from .spl import LANGUAGE as SPL_LANGUAGE
from .spl import parse_spl
from .spl_ir import lower as lower_spl
from .wazuh import DIALECT as WAZUH_DIALECT
from .wazuh import LANGUAGE as WAZUH_LANGUAGE
from .wazuh import parse_wazuh
from .wazuh_ir import lower as lower_wazuh

__all__ = [
    "Diagnostic",
    "parse_aql", "lower_aql", "render_aql", "cre_from_ir",
    "AQL_DIALECT", "AQL_LANGUAGE",
    "parse_yaral", "lower_yaral", "render_yaral",
    "YARAL_DIALECT", "YARAL_LANGUAGE",
    "parse_kql", "lower_kql",
    "KQL_DIALECT", "KQL_LANGUAGE",
    "parse_wazuh", "lower_wazuh",
    "WAZUH_DIALECT", "WAZUH_LANGUAGE",
    "parse_spl", "lower_spl",
    "SPL_DIALECT", "SPL_LANGUAGE",
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
