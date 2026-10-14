"""NetBox source adapter re-exporting the core netbox module."""
from __future__ import annotations

from ai_log_analyzer.netbox import *  # noqa: F401,F403
from ai_log_analyzer.netbox import (
    NetBoxClient,
    NetBoxError,
    _termination_device_name,
    build_site_manifest,
    enrich_host,
    enrich_hosts,
    is_enabled,
)

__all__ = [
    "NetBoxClient",
    "NetBoxError",
    "build_site_manifest",
    "enrich_host",
    "enrich_hosts",
    "is_enabled",
    "_termination_device_name",
]
