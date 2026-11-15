"""The browser-facing half of RuleForge: a local HTTP API and the GUI it serves.

Nothing in here knows a vendor's syntax. The API asks the `dialects` registry by
key and hands back IR, which is what keeps eight dialects from becoming eight
front ends.
"""

from __future__ import annotations

from .api import Api, MAX_BODY_BYTES, RuleForgeHandler, build_server, serve

__all__ = ["Api", "RuleForgeHandler", "build_server", "serve", "MAX_BODY_BYTES"]
