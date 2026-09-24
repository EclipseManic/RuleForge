"""Real structural parsers per query dialect.

Before this module, validation was regex heuristics: "contains a pipeline stage",
"contains the word where". That cannot tell a well-formed SPL pipeline from a
malformed one, and it cannot tell a syntactically valid query from one that
silently means something different. The professional bar is a structural parse:
tokenize with quote awareness, then check the grammar's own shape rules.

Each parser returns a list of problems; empty means the structure parsed. The
parsers are intentionally conservative - they check structure that is unambiguous
from the dialect grammar, not full type checking, and they never claim to replace
the vendor engine. Anything they cannot decide is reported as a warning upstream,
never silently passed.
"""
from __future__ import annotations

import re
from typing import Any


def strip_literals(text: str) -> str:
    """Replace string/regex literals with empty quotes so structure can be scanned."""
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in "\"'":
            quote = char
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
            out.append('""')
            continue
        out.append(char)
        index += 1
    return "".join(out)


def unterminated_literals(text: str) -> list[str]:
    """Report string literals that are opened and never closed.

    strip_literals treats an unterminated quote as if a closing quote existed, so
    malformed input could otherwise reach the end of a parse and receive a
    "structure-parsed" claim despite being unrunnable.

    The scan is context-aware, because a naive quote counter is wrong in both
    directions. It skips comment lines and block comments, and skips regex literals
    (/.../), so `// analyst's note` and `title: Analyst's rule` are not reported as
    unterminated strings. Conversely a quote inside a comment no longer closes a
    string opened before it, which previously let malformed input pass unflagged.
    """
    problems: list[str] = []
    active: str | None = None
    opened_at = 0
    index = 0
    in_block_comment = False
    length = len(text)
    while index < length:
        char = text[index]
        if in_block_comment:
            if text.startswith("*/", index):
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue
        if active is not None:
            if char == "\\":
                index += 2
                continue
            if char == active:
                active = None
            index += 1
            continue
        # Outside a literal: comments, regex literals and plain text.
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline == -1 else newline
            continue
        if text.startswith("/*", index):
            in_block_comment = True
            index += 2
            continue
        if char == "#" and not text.startswith("##", index):
            newline = text.find("\n", index)
            index = length if newline == -1 else newline
            continue
        if char == "/" and index + 1 < length and not text.startswith("//", index):
            closing = text.find("/", index + 1)
            newline = text.find("\n", index)
            # A slash pair with no intervening newline or quote is a regex literal.
            if closing != -1 and (newline == -1 or closing < newline) and '"' not in text[index:closing] \
                    and "'" not in text[index:closing]:
                index = closing + 1
                continue
        if char in "\"'":
            # A quote only opens a literal when it follows something that can take a
            # value - an operator, delimiter, or YAML key. An apostrophe in the middle
            # of a word is ordinary text: `title: Analyst's rule`, `/foo'bar/`, and
            # `O'Brien` must not be reported as unterminated strings.
            previous = text[index - 1] if index else ""
            opener = previous in "=:,<>()[]{}!?+-|&*% \t" or previous in "\r\n"
            if opener:
                active = char
                opened_at = index
        index += 1
    if active is not None:
        label = "double" if active == '"' else "single"
        problems.append(f"Unterminated {label}-quoted string starting on line {text.count(chr(10), 0, opened_at) + 1}.")
    return problems


def _drop_comments(bare: str) -> str:
    """Remove full-line comments so a rendered rule header is not parsed as a query.

    `#` starts a comment in SPL/YARA-L and in rendered headers, `//` in CQL/EQL and
    rendered headers, `--` in AQL. Only whole lines are dropped: a trailing `--`
    comment after a WHERE clause is valid AQL and must not remove the clause.
    """
    return "\n".join(line for line in bare.splitlines()
                     if not line.strip().startswith(("#", "//", "--")))


def _balanced(bare: str) -> list[str]:
    problems: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int]] = []
    for line_no, line in enumerate(bare.splitlines(), 1):
        for char in line:
            if char in "([{":
                stack.append((char, line_no))
            elif char in ")]}":
                if not stack:
                    problems.append(f"Unmatched closing '{char}' on line {line_no}.")
                elif stack[-1][0] != pairs[char]:
                    opener, opened_at = stack[-1]
                    problems.append(f"'{opener}' opened on line {opened_at} is closed by '{char}' on line {line_no}.")
                    stack.pop()
                else:
                    stack.pop()
    for opener, opened_at in stack:
        problems.append(f"'{opener}' opened on line {opened_at} is never closed.")
    return problems


# --- SPL -------------------------------------------------------------------

SPL_COMMANDS = {
    "search", "where", "eval", "stats", "streamstats", "eventstats", "tstats",
    "transaction", "join", "selfjoin", "append", "appendpipe", "lookup",
    "inputlookup", "inputcsv", "makeresults", "rename", "regex", "rex", "spath",
    "fillnull", "head", "tail", "sort", "dedup", "mvexpand", "collect", "summariesonly",
    "multisearch", "gentimes", "format", "union", "walk", "foreach", "map", "untable",
    "convert", "nominal", "tags", "untag", "collect", "outputlookup", "return", "sort",
}

# Commands that open a subsearch context, which legitimately nests parentheses.
SPL_SUBSEARCH = {"join", "selfjoin", "append", "appendpipe", "transaction", "search",
                 "inputlookup", "lookup", "multisearch", "union", "where", "format", "rex"}

SPL_FIELD_FUNCS = {"isnotnull", "isnull", "like", "match", "if", "nullif", "true", "false", "len", "lower", "upper"}


def parse_spl(query: str) -> list[str]:
    """Structural SPL check: starts with a search term or command, valid pipe chain,
    balanced delimiters, and known command names."""
    problems: list[str] = []
    bare = strip_literals(query)
    problems.extend(_balanced(bare))
    lines = [line.strip() for line in _drop_comments(bare).splitlines() if line.strip()]
    if not lines:
        return ["SPL output is empty."]
    first = lines[0]
    if not (first.startswith("|") or re.match(r"^(?:search|index\s*=|tstats\s|streamstats\s)", first, re.IGNORECASE)
            or re.match(r"^\w[\w.\-*]*\s*=", first)):
        problems.append("SPL should start with a search term, index=..., or a command.")
    saw_stage = False
    for line in lines:
        for stage in [part.strip() for part in re.split(r"(?<!\|)\|(?!\|)", line) if part.strip()]:
            if not stage.startswith("|"):
                continue
            name_match = re.match(r"\|\s*([A-Za-z_][A-Za-z0-9_]*)", stage)
            if not name_match:
                problems.append("Pipeline stage '|' is missing a command name.")
                continue
            name = name_match.group(1).lower()
            if name not in SPL_COMMANDS:
                problems.append(f"Unknown SPL command '{name_match.group(1)}'.")
    # A search term alone is a complete SPL query (index=auth failed=1 is valid), so a
    # missing pipeline stage is an authoring note, not malformed output. Reported by
    # spl_advice so a rule with no pipeline is still surfaced to the analyst.
    if re.search(r"\b(?:and|or|not)\s*(?:\||$)", bare, re.IGNORECASE | re.MULTILINE):
        problems.append("SPL boolean expression ends with a dangling and/or.")
    return problems


# --- KQL -------------------------------------------------------------------

KQL_OPERATORS = {
    "==", "!=", "<", "<=", ">", ">=", "and", "or", "not", "in", "in~", "has", "has_any",
    "has_all", "contains", "contains_cs", "startswith", "endswith", "matches regex",
    "between", "!in", "!contains", "!startswith", "!endswith", "!has", "where", "project",
    "summarize", "extend", "join", "top", "sort", "parse", "parse-kv", "limit", "count",
    "distinct", "make-series", "mv-expand", "union", "take", "sample", "evaluate",
    "lookup", "externaldata", "datatable", "range", "print", "render", "invoke",
    "getschema", "search", "find", "getsummaries", "cluster", "database", "not_contains",
}

KQL_TABULAR = {"summarize", "parse", "parse-kv", "extend", "project", "project-away",
               "project-rename", "mv-expand", "make-series", "top", "sort", "limit",
               "take", "sample", "distinct", "count", "range", "render", "evaluate",
               "lookup", "externaldata", "datatable", "join", "union"}


def parse_kql(query: str) -> list[str]:
    """Structural KQL check: balanced delimiters, well-formed pipe stages, and no
    dangling boolean operator.

    A bare expression (e.g. `ProcessName == "x" and CommandLine contains "y"`) is a
    valid KQL expression fragment, so a missing pipeline is advisory, not malformed -
    target_warnings reports it, and target_check does not fail on it.
    """
    problems: list[str] = []
    bare = strip_literals(query)
    problems.extend(_balanced(bare))
    lines = [line.strip() for line in _drop_comments(bare).splitlines() if line.strip()]
    if not lines:
        return ["KQL output is empty."]
    for line in lines:
        # Every pipe introduces a stage, so every segment after the first must begin with
        # an operator name. That catches both `| | where` and a trailing `| `.
        for stage in line.split("|")[1:]:
            if not re.match(r"\s*[A-Za-z][A-Za-z0-9_-]*", stage):
                problems.append("Pipe '|' in KQL is missing an operator name.")
    if re.search(r"\b(?:and|or|not)\s*(?:\||$)", bare, re.IGNORECASE | re.MULTILINE):
        problems.append("KQL boolean expression ends with a dangling and/or/not.")
    where_clauses = re.findall(r"\|?\s*where\s+(.+)", "\n".join(lines), re.IGNORECASE)
    for clause in where_clauses:
        # _verify_expr wraps and re-parses; that would call parse_kql on the wrapper,
        # which contains the same where clause, forever. Skip wrapper-shaped input.
        if "|" in clause:
            continue
        problems.extend(_verify_expr(clause.strip(), "kql"))
    for match in re.finditer(r"\|\s*join\b(.*)", bare, re.IGNORECASE):
        tail = match.group(1)
        if not re.search(r"\bon\b|=|\bkind\s*=", tail, re.IGNORECASE):
            problems.append("KQL join is missing an 'on' condition.")
    return problems


def kql_advice(query: str) -> list[str]:
    """Non-blocking KQL notes: the output is a valid expression but not a full query."""
    bare = strip_literals(query)
    if not re.search(r"^\s*\|", bare) and not re.search(r"^\s*where\b", bare, re.IGNORECASE):
        if not re.search(r"\|\s*[A-Za-z]", bare):
            return ["KQL is an expression fragment: add a table and '| where ...' to make it a runnable query."]
    if re.search(r"\bwhere\b[^\n]*\bwhere\b", bare, re.IGNORECASE):
        return ["KQL has two 'where' clauses in one stage; chain them with 'and'."]
    return []


# --- AQL -------------------------------------------------------------------

AQL_CLAUSES = ("select", "from", "where", "group", "having", "order", "last", "first")


def parse_aql(query: str) -> list[str]:
    """Structural AQL check: required SELECT/FROM, clause order, LAST window,
    balanced delimiters."""
    problems: list[str] = []
    bare = strip_literals(query)
    problems.extend(_balanced(bare))
    collapsed = " ".join(bare.split())
    lowered = collapsed.lower()
    if not re.search(r"\bselect\b", lowered):
        problems.append("AQL must contain SELECT.")
    if not re.search(r"\bfrom\b", lowered):
        problems.append("AQL must contain FROM.")
    # DISTINCT modifies the select list; it is not an ordered clause, so it is removed
    # before positions are compared. Treating it as a clause rejected valid
    # `SELECT DISTINCT x FROM ...` queries.
    order_source = re.sub(r"\bselect\s+distinct\b", "select", lowered)
    positions = [(pos if pos >= 0 else order_source.find(f"{clause} "), clause)
                 for pos, clause in ((order_source.find(f"{clause} "), clause) for clause in AQL_CLAUSES)]
    order = [(pos, clause) for pos, clause in positions if pos >= 0]
    order.sort()
    expected = [clause for _, clause in order]
    canonical = [clause for clause in AQL_CLAUSES if clause in expected]
    if expected and expected != canonical:
        problems.append(f"AQL clauses out of order: found {' -> '.join(expected)}.")
    if "having" in expected and "group" not in expected:
        problems.append("AQL HAVING requires GROUP BY.")
    if re.search(r"\bselect\s+distinct\b", lowered) and "group" in expected:
        problems.append("AQL DISTINCT cannot be combined with GROUP BY.")
    if not re.search(r"\blast\s+\d+", lowered) and not re.search(r"\btimestamp\s*(?:between|>=|<=)", lowered):
        problems.append("AQL has no time bound; add LAST n MINUTES or a timestamp filter to avoid an unbounded scan.")
    return problems


# --- EQL -------------------------------------------------------------------

EQL_EVENT_CATEGORIES = {
    "process", "network", "file", "registry", "dns", "authentication", "library",
    "driver", "process_access", "module", "session", "any",
}

EQL_COMPARISONS = {"==", "!=", "<", "<=", ">", ">=", ":", "in~", "in", "not in", "not in~"}


def parse_eql(query: str) -> list[str]:
    """Structural EQL check. EQL is genuinely parseable, so this is the strongest
    non-pySigma check in the tool: event category, where clause, and sequence shape."""
    problems: list[str] = []
    bare = strip_literals(query)
    problems.extend(_balanced(bare))
    # Rendered rules carry a commented header (name, severity, index pattern); only the
    # query body is EQL, so comments are dropped before matching the grammar.
    text = " ".join(_drop_comments(bare).split())
    if not text:
        return ["EQL output is empty."]
    lowered = text.lower()
    # A custom-threshold rule is the Kibana detections-API YAML body, not an EQL query.
    # It is validated as such (see parse_threshold_rule) rather than forced into the
    # EQL grammar, which would produce a false failure.
    if re.search(r"^\s*type:\s*[\"']?threshold", query, re.IGNORECASE | re.MULTILINE):
        # A threshold rule is a key/value body, not a query language: its values are
        # quoted strings, so it is validated verbatim (comments removed) rather than
        # through strip_literals, which would blank every value it needs to check.
        return parse_threshold_rule(_drop_comments(query))
    if lowered.startswith("sequence"):
        if "with maxspan=" not in lowered:
            problems.append("EQL sequence should bind the time window with 'with maxspan=<duration>'.")
        match = re.search(r"with\s+maxspan\s*=\s*([0-9]+[a-z]+)", lowered)
        if match and not re.fullmatch(r"[1-9][0-9]{0,2}(?:s|m|h|d)", match.group(1)):
            problems.append(f"EQL maxspan '{match.group(1)}' is not a valid duration (use 30s, 5m, 1h, 1d).")
        stages = re.findall(r"(!?)\[\s*([a-z_]+)\s+where\s+", lowered)
        if not stages:
            problems.append("EQL sequence has no stages of the form [event where condition].")
        for _, category in stages:
            if category not in EQL_EVENT_CATEGORIES:
                problems.append(f"EQL event category '{category}' is not a valid category.")
        if re.search(r"(!?)\[\s*([a-z_]+)\s+where\s*\]", lowered):
            problems.append("EQL stage has an empty where clause.")
        return problems
    match = re.match(r"^([a-z_]+)\s+where\s+(.+)$", lowered)
    if not match:
        problems.append("EQL must be '<event-category> where <condition>' or a 'sequence' query.")
        return problems
    category, condition = match.group(1), match.group(2)
    if category not in EQL_EVENT_CATEGORIES:
        problems.append(f"EQL event category '{category}' is not a valid category.")
    if not condition.strip():
        problems.append("EQL where clause is empty.")
    if re.search(r"\b(?:and|or|not)\s*$", condition):
        problems.append("EQL condition ends with a dangling and/or/not.")
    if re.search(r"\bwhere\s+where\b", lowered):
        problems.append("EQL has a duplicated 'where'.")
    if not re.search(r"[<>=!:]|\b(?:in|like|wildcard|regex|prefix|regress)\b", condition):
        problems.append("EQL where clause has no comparison; bare words are not valid conditions.")
    return problems + _verify_expr(condition, "eql")


THRESHOLD_REQUIRED = ("type", "schedule", "index", "query", "group_by", "threshold",
                      "window", "min_window", "threshold_window")


def parse_threshold_rule(text: str) -> list[str]:
    """Structural check for an Elastic custom-threshold rule body.

    These are the keys the Kibana detections API requires, plus the two semantics that
    silently change an alert's meaning: the comparator and the window durations.
    """
    problems: list[str] = []
    for key in THRESHOLD_REQUIRED:
        if not re.search(rf"^\s*{key}\s*:", text, re.IGNORECASE | re.MULTILINE):
            problems.append(f"Elastic threshold rule has no '{key}:' field.")
    if not re.search(r"^\s*type\s*:\s*[\"']?threshold", text, re.IGNORECASE | re.MULTILINE):
        problems.append("Elastic threshold rule must declare 'type: threshold'.")
    if not re.search(r"\bquery\s*:\s*[|>]?\s*-?\s*\S", text, re.IGNORECASE):
        problems.append("Elastic threshold rule has an empty 'query:' block.")
    if re.search(r"^\s*threshold\s*:\s*\{\s*\}", text, re.IGNORECASE | re.MULTILINE):
        problems.append("Elastic threshold rule has an empty 'threshold:' block.")
    match = re.search(r"comparator\s*:\s*[\"']?([A-Za-z<>!=]+)", text)
    if match and match.group(1) not in (">=", ">", "<=", "<", "==", "!="):
        problems.append(f"Elastic threshold comparator '{match.group(1)}' is not valid.")
    elif not match:
        problems.append("Elastic threshold rule has no comparator.")
    for key in ("window", "min_window", "threshold_window"):
        duration = re.search(rf"{key}\s*:\s*[\"']?([0-9]+[smhd])\b", text)
        if duration and duration.group(1)[0] == "0":
            problems.append(f"Elastic threshold '{key}' must be a positive duration.")
    if re.search(r"cardinality\s*:\s*[\"']?(\w+)", text):
        cardinality = re.search(r"cardinality\s*:\s*[\"']?(\w+)", text).group(1).lower()
        if cardinality not in ("single", "cardinality"):
            problems.append(f"Elastic threshold cardinality '{cardinality}' must be 'single' or 'cardinality'.")
    return problems


# --- CQL -------------------------------------------------------------------

CQL_PIPELINE = {
    "groupby", "bucket", "timechart", "join", "lookup", "tail", "head", "sort", "rename",
    "field", "format", "regex", "parse", "expand", "rollup", "rare", "top", "stats",
    "table", "eval", "in", "match", "make_set", "concat", "count", "select", "where",
}


def parse_cql(query: str) -> list[str]:
    """Structural CQL check: '#repo' scope, balanced parens, and real pipeline calls."""
    problems: list[str] = []
    bare = strip_literals(query)
    problems.extend(_balanced(bare))
    if not re.search(r"#\s*repo\s*=", bare, re.IGNORECASE):
        problems.append("CQL must scope to a repository with '#repo = \"name\"'.")
    # A pipeline call is a function invocation after a pipe: | groupBy(...), | table(...).
    # A bare boolean expression after the scope header is a valid CQL filter, so the
    # missing-function shape is advice, not a structural failure.
    if not re.search(r"\|\s*[A-Za-z_][A-Za-z0-9_]*\s*[\(\{]", bare):
        pass
    for call in re.finditer(r"\|\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", bare):
        name = call.group(1).lower()
        if name not in CQL_PIPELINE:
            problems.append(f"Unknown CQL function '{call.group(1)}'.")
    if re.search(r"\|\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", bare) and re.search(r"=\s*;|\(\s*\)\s*\|", bare):
        problems.append("CQL has an empty function argument list.")
    return problems


# --- YARA-L ----------------------------------------------------------------


def parse_yara_l(query: str) -> list[str]:
    """Structural YARA-L check: rule/meta/events/match/condition blocks and event
    numbering consistency."""
    problems: list[str] = []
    text = strip_literals(query)
    problems.extend(_balanced(text))
    if not re.search(r"\brule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", text):
        problems.append("YARA-L must declare 'rule <name> {'.")
        return problems
    # meta is optional in YARA-L; events/condition are the required blocks, and match is
    # required only for multi-event rules (a single-event rule has no grouping window).
    for block in ("events", "condition"):
        if not re.search(rf"\b{block}\s*:", text):
            problems.append(f"YARA-L rule has no '{block}:' section.")
    has_event_var = bool(re.search(r"\$e\d+\s*\.", text))
    has_match = bool(re.search(r"\bmatch\s*:", text))
    if has_event_var and not has_match:
        problems.append("YARA-L rule binds event variables but has no 'match:' section.")
    if not re.search(r"\bmeta\s*:", text):
        problems.append("YARA-L rule has no 'meta:' section; add author and severity before deployment.")
    variables = {int(n) for n in re.findall(r"\$e(\d+)\s*\.", text)}
    if variables:
        expected = set(range(1, max(variables) + 1))
        missing = sorted(expected - variables)
        if missing:
            problems.append(f"YARA-L references ${', $'.join('e' + str(n) for n in missing)} without defining them in events.")
    condition_vars = set(re.findall(r"\$(e\d+)\b", re.search(r"\bcondition\s*:(.*)$", text, re.DOTALL).group(1)
                                     if re.search(r"\bcondition\s*:(.*)$", text, re.DOTALL) else ""))
    if condition_vars and not (condition_vars & {f"e{n}" for n in variables}):
        problems.append("YARA-L condition references event variables that are not defined in events.")
    return problems


# --- Sigma -----------------------------------------------------------------


def parse_sigma(query: str) -> list[str]:
    """Structural Sigma check: required top-level sections, detection block shape,
    and condition/key references that actually exist."""
    from safe_yaml import safe_yaml_load

    problems: list[str] = []
    try:
        document = safe_yaml_load(query)
    except ValueError as error:
        return [f"Sigma output is not valid YAML: {error}."]
    if not isinstance(document, dict):
        return ["Sigma output is not a YAML mapping."]
    for section in ("title", "detection"):
        if not document.get(section):
            problems.append(f"Sigma output has no '{section}'.")
    detection = document.get("detection")
    if not isinstance(detection, dict):
        problems.append("Sigma 'detection' must be a mapping.")
        return problems
    condition = detection.get("condition")
    if not condition:
        problems.append("Sigma detection has no 'condition'.")
    else:
        selectors = re.findall(r"\b([a-z][a-z0-9_]*(?:\s*\|\s*[a-z][a-z0-9_]*)*)\b", str(condition).lower())
        for selector in re.findall(r"[a-z][a-z0-9_]*(?:\s*\|\s*[a-z][a-z0-9_]*)*", str(condition).lower()):
            for name in [part.strip() for part in selector.split("|")]:
                if name and name not in detection and name not in {"and", "or", "not", "of", "them", "all", "1"}:
                    problems.append(f"Sigma condition references '{name}', which is not a selection in detection.")
    for name, value in detection.items():
        if name == "condition" or not isinstance(value, dict):
            continue
        for key, entry in value.items():
            if isinstance(entry, dict) and not any(op in entry for op in
                    ("contains", "equals", "startswith", "endswith", "re", "all", "base64", "base64offset", "windash", "cidr")):
                problems.append(f"Sigma selection '{name}.{key}' has no recognized condition operator.")
    return problems


EQUIVALENT_SYNTAX = {
    "splunk": "spl", "wazuh": "spl", "sentinel": "kql", "elastic": "eql",
    "qradar": "aql", "falcon": "cql", "google_secops": "yara", "sigma": "sigma",
}


_VERIFYING: set[str] = set()


def _verify_expr(expr: str, syntax: str) -> list[str]:
    """Parse a rendered expression fragment with the same structural parsers.

    This is the check that matters most: a bare boolean expression has no pipeline
    to inspect, so the fragment is wrapped in the minimal valid query for its dialect
    and parsed. That is how a missing comparison or a dangling operator in the
    generated logic gets caught rather than shipped.
    """
    wrapped = {
        "spl": f'index=_audit | search {expr}',
        "kql": f'Table\n| where {expr}',
        "eql": f'process where {expr}',
        "aql": f'SELECT * FROM events WHERE {expr} LAST 5 MINUTES',
        "cql": f'#repo="_audit"\n| {expr}',
        "yara": f'rule _audit_check {{\n  events:\n    {expr}\n  condition:\n    $e\n}}',
    }.get(syntax)
    if wrapped is None or syntax in _VERIFYING:
        return []
    _VERIFYING.add(syntax)
    try:
        problems = structure_check(EQUIVALENT_SYNTAX_REVERSE.get(syntax, ""), wrapped)
    finally:
        _VERIFYING.discard(syntax)
    # Drop wrapper-shape complaints: they describe our scaffold, not the expression.
    noise = ("must contain SELECT", "must contain FROM", "clauses out of order",
             "must scope to a repository", "no time bound", "no match: block",
             "tabular operator", "no 'on' condition", "duplicate")
    return [p for p in problems if not any(token in p for token in noise)]


EQUIVALENT_SYNTAX_REVERSE = {v: k for k, v in EQUIVALENT_SYNTAX.items()}


PARSERS = {
    "splunk": parse_spl,
    "sentinel": parse_kql,
    "elastic": parse_eql,
    "qradar": parse_aql,
    "falcon": parse_cql,
    "google_secops": parse_yara_l,
    "sigma": parse_sigma,
}


def structure_check(siem: str, query: str) -> list[str]:
    """Run the dialect's structural parser. Unknown dialects get no claim either way."""
    parser = PARSERS.get(str(siem))
    if parser is None:
        return []
    try:
        return unterminated_literals(query) + parser(query)
    except (ValueError, TypeError) as error:
        return [f"Could not structurally parse {siem} output: {error}"]


def spl_advice(query: str) -> list[str]:
    """Non-blocking SPL notes."""
    bare = _drop_comments(strip_literals(query))
    if not re.search(r"\|\s*[A-Za-z_]", bare):
        return ["SPL has no pipeline stage; the rule matches on raw search terms only."]
    return []


def cql_advice(query: str) -> list[str]:
    """Non-blocking CQL notes: a raw-field filter is valid but unbounded."""
    bare = _drop_comments(strip_literals(query))
    if not re.search(r"\|\s*[A-Za-z_][A-Za-z0-9_]*\s*[\(\{]", bare):
        return ["CQL filters on raw fields; add a pipeline stage (groupBy/table/top) to bound and shape the results."]
    return []


ADVICE = {"sentinel": kql_advice, "splunk": spl_advice, "falcon": cql_advice}


def structure_advice(siem: str, query: str) -> list[str]:
    """Advisory notes for output that parses but is not yet a runnable query."""
    checker = ADVICE.get(str(siem))
    if checker is None:
        return []
    try:
        return checker(query)
    except (ValueError, TypeError):
        return []


def structure_summary(siem: str, query: str) -> dict[str, Any]:
    """Structured facts about a query, for the UI and for analysis."""
    bare = strip_literals(query or "")
    operators = [word.upper() for word in re.findall(r"\b(?:AND|OR|NOT|EXCEPT|IN|NIN)\b", bare, re.IGNORECASE)]
    depth = 0
    max_depth = 0
    for char in bare:
        if char in "([":
            depth += 1
            max_depth = max(max_depth, depth)
        elif char in ")]":
            depth = max(0, depth - 1)
    stages = len(re.findall(r"\|\s*[A-Za-z_]", bare))
    return {
        "dialect": str(siem),
        "operators": operators,
        "operator_count": len(operators),
        "group_depth": max_depth,
        "pipeline_stages": stages,
        "structured": str(siem) in PARSERS,
    }
