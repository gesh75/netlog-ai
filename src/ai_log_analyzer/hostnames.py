"""One definition of "short host name" shared by the classifier and the
correlation / suppression engines."""
from __future__ import annotations

import ipaddress


def is_ip_literal(host: str) -> bool:
    """True for IPv4 / IPv6 literals, with or without [brackets]."""
    try:
        ipaddress.ip_address((host or "").strip().strip("[]"))
    except ValueError:
        return False
    return True


def short_host(hostname: str, *, fold: bool = True) -> str:
    """Strip the DNS domain from a device name; never split an IP literal.

    ``10.0.0.1`` stays ``10.0.0.1`` (a plain ``split(".")[0]`` turned every
    IP-addressed device into ``10``). Names are lowercased when ``fold``.
    Only the first DNS label is kept, so ``edge1.dc1.example.com`` and
    ``edge1.dc2.example.com`` still share ``edge1``.
    """
    host = (hostname or "").strip()
    if not host:
        return ""
    if not is_ip_literal(host):
        host = host.split(".")[0]
    return host.lower() if fold else host
