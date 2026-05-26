"""Build a netlog-ai site bundle from the local docker-based DCN FRR lab.

Reads the 10 frr.conf files under network-lab/configs/, sanitizes them, and
writes sites/dcn-lab/ with one .txt per device + manifest.json.

Mapping mirrors network-lab/docker-compose.yml container_name -> ./configs/<dir>.

Usage:
    python scripts/import_dcn_lab.py
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

# netlog-ai sanitizer is a sibling package
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ai_log_analyzer.sanitize import sanitize_report  # noqa: E402


SITE_ID = "dcn-lab"
SITE_NAME = "DCN-LAB"
NETLOG_AI_ROOT = Path(__file__).resolve().parents[1]
SITES_DIR = NETLOG_AI_ROOT / "sites" / SITE_ID
LAB_CONFIGS_DIR = (
    NETLOG_AI_ROOT.parents[1] / "network-lab" / "configs"
).resolve()


@dataclass(frozen=True)
class LabNode:
    hostname: str
    config_dir: str   # subdir under network-lab/configs/
    asn: int
    role: str         # core | edge | dist
    pop: str          # de-fra | uk-lon | nl-ams | us-nyc


FABRIC: tuple[LabNode, ...] = (
    LabNode("de-fra-core-01", "r1",  65001, "core", "de-fra"),
    LabNode("de-fra-core-02", "r2",  65002, "core", "de-fra"),
    LabNode("uk-lon-core-01", "r3",  65003, "core", "uk-lon"),
    LabNode("nl-ams-core-01", "r4",  65004, "core", "nl-ams"),
    LabNode("us-nyc-core-01", "r5",  65005, "core", "us-nyc"),
    LabNode("de-fra-edge-01", "sw1", 65006, "edge", "de-fra"),
    LabNode("uk-lon-dist-01", "sw2", 65010, "dist", "uk-lon"),
    LabNode("uk-lon-edge-01", "sw3", 65007, "edge", "uk-lon"),
    LabNode("nl-ams-edge-01", "sw4", 65008, "edge", "nl-ams"),
    LabNode("de-fra-dist-01", "sw5", 65009, "dist", "de-fra"),
)


def function_for_role(role: str) -> tuple[str, str]:
    if role in {"core", "edge"}:
        return "router", "rt"
    if role == "dist":
        return "switch", "sw"
    return "unknown", "??"


def main() -> int:
    SITES_DIR.mkdir(parents=True, exist_ok=True)
    manifest_devices: list[dict] = []

    print(f"Importing {len(FABRIC)} DCN lab nodes -> {SITES_DIR}")
    for node in FABRIC:
        src = LAB_CONFIGS_DIR / node.config_dir / "frr.conf"
        if not src.is_file():
            print(f"  [SKIP] {node.hostname}: missing {src}", file=sys.stderr)
            continue

        raw = src.read_text(encoding="utf-8")
        report = sanitize_report(raw, mask_pii=False)
        out_name = f"{node.hostname}.txt"
        (SITES_DIR / out_name).write_text(report["sanitized"], encoding="utf-8")

        function_name, fcode = function_for_role(node.role)
        manifest_devices.append({
            "hostname": node.hostname,
            "file": out_name,
            "platform": "frr",
            "vendor": "frr",
            "function": function_name,
            "function_code": fcode,
            "role": node.role,
            "pop": node.pop,
            "asn": node.asn,
            "rack": None,
            "redacted": report["total"],
            "by_rule": report["by_rule"],
            "orig_bytes": len(raw.encode("utf-8")),
            "sanitized_bytes": len(report["sanitized"].encode("utf-8")),
        })
        print(
            f"  [OK]   {node.hostname:16} role={node.role:4} pop={node.pop:6} "
            f"asn={node.asn} bytes={len(report['sanitized']):>4}"
        )

    manifest = {
        "site": SITE_NAME,
        "vendor": "frr",
        "topology": (
            "Multi-region FRR lab — 5 core + 3 edge + 2 dist across "
            "DE-FRA/UK-LON/NL-AMS/US-NYC, eBGP full mesh + OSPF area 0"
        ),
        "fabric": "multi-region-ebgp",
        "source": "network-lab/configs/ (docker-compose)",
        "devices": manifest_devices,
    }
    (SITES_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"\nManifest: {SITES_DIR / 'manifest.json'} ({len(manifest_devices)} devices)")
    return 0 if manifest_devices else 2


if __name__ == "__main__":
    raise SystemExit(main())
