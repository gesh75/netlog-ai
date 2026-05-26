"""Pull configs from the running clab-clos-evpn fabric, sanitize them, and
write a netlog-ai site bundle at sites/clab-clos-evpn/.

Vendors:
  - Nokia SR Linux  -> `sr_cli info`
  - Arista cEOS     -> `Cli -p 15 -c "show running-config"`
  - FRR             -> `vtysh -c "show running-config"`

Hosts are skipped (no config — Linux network-multitool containers).

Usage:
    python scripts/import_clab_clos_evpn.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# netlog-ai sanitizer is a sibling package
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ai_log_analyzer.sanitize import sanitize_report  # noqa: E402


SITE_ID = "clab-clos-evpn"
SITE_NAME = "CLAB-CLOS-EVPN"
SITES_DIR = Path(__file__).resolve().parents[1] / "sites" / SITE_ID


@dataclass(frozen=True)
class FabricNode:
    hostname: str
    container: str
    vendor: str          # nokia-srl | arista-eos | frr
    platform: str        # srl | eos | frr — netlog-ai classifier hint
    role: str            # spine | leaf
    rack: str | None


FABRIC: tuple[FabricNode, ...] = (
    FabricNode("spine1", "clab-clos-evpn-spine1", "nokia-srl",  "srl", "spine", None),
    FabricNode("spine2", "clab-clos-evpn-spine2", "arista-eos", "eos", "spine", None),
    FabricNode("spine3", "clab-clos-evpn-spine3", "frr",        "frr", "spine", None),
    FabricNode("leaf1",  "clab-clos-evpn-leaf1",  "arista-eos", "eos", "leaf",  "rack-1"),
    FabricNode("leaf2",  "clab-clos-evpn-leaf2",  "nokia-srl",  "srl", "leaf",  "rack-1"),
    FabricNode("leaf3",  "clab-clos-evpn-leaf3",  "frr",        "frr", "leaf",  "rack-2"),
    FabricNode("leaf4",  "clab-clos-evpn-leaf4",  "arista-eos", "eos", "leaf",  "rack-2"),
    FabricNode("leaf5",  "clab-clos-evpn-leaf5",  "nokia-srl",  "srl", "leaf",  "rack-3"),
    FabricNode("leaf6",  "clab-clos-evpn-leaf6",  "frr",        "frr", "leaf",  "rack-3"),
)


def fetch_config(node: FabricNode) -> str:
    """Return the running config text for a fabric node, via `docker exec`."""
    if node.vendor == "nokia-srl":
        cmd = ["docker", "exec", node.container, "sr_cli", "info"]
    elif node.vendor == "arista-eos":
        cmd = ["docker", "exec", node.container, "Cli", "-p", "15", "-c", "show running-config"]
    elif node.vendor == "frr":
        cmd = ["docker", "exec", node.container, "vtysh", "-c", "show running-config"]
    else:
        raise ValueError(f"unknown vendor {node.vendor!r}")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{node.hostname}: exit {result.returncode}: {result.stderr.strip()[:200]}")
    return result.stdout


def function_code(role: str) -> tuple[str, str]:
    if role == "spine":
        return "router", "rt"
    if role == "leaf":
        return "switch", "sw"
    return "unknown", "??"


def main() -> int:
    SITES_DIR.mkdir(parents=True, exist_ok=True)
    manifest_devices: list[dict] = []

    print(f"Importing {len(FABRIC)} nodes to {SITES_DIR}")
    for node in FABRIC:
        try:
            raw = fetch_config(node)
        except Exception as exc:
            print(f"  [SKIP] {node.hostname}: {exc}", file=sys.stderr)
            continue

        report = sanitize_report(raw, mask_pii=False)
        out_name = f"{node.hostname}.txt"
        (SITES_DIR / out_name).write_text(report["sanitized"], encoding="utf-8")

        function_name, fcode = function_code(node.role)
        manifest_devices.append({
            "hostname": node.hostname,
            "file": out_name,
            "platform": node.platform,
            "vendor": node.vendor,
            "function": function_name,
            "function_code": fcode,
            "role": node.role,
            "rack": node.rack,
            "redacted": report["total"],
            "by_rule": report["by_rule"],
            "orig_bytes": len(raw.encode("utf-8")),
            "sanitized_bytes": len(report["sanitized"].encode("utf-8")),
        })
        print(
            f"  [OK]   {node.hostname:7} platform={node.platform:4} role={node.role:5} "
            f"redactions={report['total']:>2} bytes={len(report['sanitized']):>5}"
        )

    manifest = {
        "site": SITE_NAME,
        "vendor": "multi (Nokia SRL + Arista cEOS + FRR)",
        "topology": "Clos EVPN-VXLAN fabric — 3 spines, 6 leafs, 6 hosts",
        "fabric": "clos-evpn",
        "devices": manifest_devices,
    }
    (SITES_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"\nManifest: {SITES_DIR / 'manifest.json'} ({len(manifest_devices)} devices)")
    return 0 if manifest_devices else 2


if __name__ == "__main__":
    raise SystemExit(main())
