"""IP and CIDR containment.

Small and separate because network predicates are the one place where a
convenient shortcut produces a confidently wrong security decision:

    `in` on strings is a prefix test, not a containment test. "10.0.0.1" is not in
    the string "10.0.0.10something", but it IS a prefix of it, and a rule using
    `contains` to mean "in this network" matches hosts it was never written for.

So this uses `ipaddress`, which parses rather than compares text.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .values import UNDECIDED, Undecided


def cidr_contains(address: Any, network: Any) -> bool | Undecided:
    """Is `address` inside `network`?

    UNDECIDED when either side is not a valid address. A malformed address is not
    "not in the network" -- that is a statement about a value nobody can read, and
    asserting it would silently drop a host the rule was meant to catch.
    """
    if not isinstance(address, str) or not isinstance(network, str):
        return UNDECIDED
    try:
        addr = ipaddress.ip_address(address.strip())
    except ValueError:
        return UNDECIDED
    try:
        net = ipaddress.ip_network(network.strip(), strict=False)
    except ValueError:
        return UNDECIDED
    if addr.version != net.version:
        # An IPv4 address against an IPv6 network is not a containment question.
        return UNDECIDED
    return addr in net


def same_network(address: Any, network: Any) -> bool | Undecided:
    """Is `address` the network's own base address (a host, not a range)?"""
    if not isinstance(address, str) or not isinstance(network, str):
        return UNDECIDED
    try:
        return ipaddress.ip_address(address.strip()) == \
            ipaddress.ip_network(network.strip(), strict=False).network_address
    except ValueError:
        return UNDECIDED
