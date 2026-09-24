"""Safe YAML loading for untrusted, analyst-pasted text.

PyYAML recurses while parsing nested flow collections, so hostile or merely malformed
input such as an unterminated `[K: K: K: ...` raises RecursionError. That escapes the
usual `except yaml.YAMLError` guard and turns a bad paste into a crash instead of a
validation message. Every parse of analyst-supplied YAML goes through this helper so the
failure mode is a clean, reportable error.
"""
from __future__ import annotations

import yaml

# Refuse absurd inputs before the parser has a chance to recurse. No legitimate Sigma
# rule, EQL threshold body or section block comes close to this.
MAX_YAML_INPUT = 512_000


def safe_yaml_load(text: str) -> object:
    """Parse YAML, converting parser failures (including recursion) into ValueError.

    Raises ValueError with a clear message on any malformed or pathological input.
    """
    if not isinstance(text, str):
        raise ValueError("YAML input must be text.")
    if len(text) > MAX_YAML_INPUT:
        raise ValueError(f"Input is too large to parse safely (limit {MAX_YAML_INPUT:,} characters).")
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid YAML: {error}") from error
    except RecursionError as error:
        raise ValueError(
            "YAML is nested too deeply to parse safely; this is usually an unterminated "
            "bracket or quote rather than a real rule."
        ) from error
