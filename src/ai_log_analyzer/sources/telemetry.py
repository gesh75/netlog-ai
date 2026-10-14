"""Optical DOM/DDM and interface counter telemetry correlation engine.

Cross-validates syslog events against numeric interface telemetry from
Prometheus, gNMI, or device state snapshots to distinguish physical fiber/SFP
degradation from QoS congestion drops or remote admin shutdowns.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any


class TelemetryDiagnosisType(str, Enum):
    OPTICAL_DEGRADATION = "optical_degradation"
    DARK_FIBER_OR_REMOTE_SHUT = "dark_fiber_or_remote_shut"
    QOS_CONGESTION_DROP = "qos_congestion_drop"
    THERMAL_SHUTDOWN = "thermal_shutdown"
    HEALTHY_PHYSICAL = "healthy_physical"


@dataclass
class InterfaceTelemetrySnapshot:
    """Point-in-time optical DOM and L1/L2 counter metrics for a network interface."""

    device: str
    interface: str
    rx_power_dbm: float | None = None
    tx_power_dbm: float | None = None
    laser_bias_ma: float | None = None
    temperature_c: float | None = None
    fcs_crc_errors_delta: int = 0
    in_discards_delta: int = 0
    out_discards_delta: int = 0
    carrier_transitions_delta: int = 0


@dataclass
class TelemetryCorrelationVerdict:
    """Result of correlating a syslog alert with interface telemetry."""

    device: str
    interface: str
    diagnosis: TelemetryDiagnosisType
    confidence: float
    summary: str
    recommended_action: str


class TelemetryCorrelator:
    """Evaluates interface telemetry snapshots against industry optical and error thresholds."""

    def __init__(
        self,
        rx_low_warn_dbm: float = -14.0,
        rx_los_crit_dbm: float = -25.0,
        temp_crit_c: float = 75.0,
        crc_storm_threshold: int = 10,
        discard_congestion_threshold: int = 500,
    ) -> None:
        self.rx_low_warn_dbm = rx_low_warn_dbm
        self.rx_los_crit_dbm = rx_los_crit_dbm
        self.temp_crit_c = temp_crit_c
        self.crc_storm_threshold = crc_storm_threshold
        self.discard_congestion_threshold = discard_congestion_threshold

    def evaluate_snapshot(
        self, snap: InterfaceTelemetrySnapshot
    ) -> TelemetryCorrelationVerdict:
        """Produce a deterministic hardware/queue diagnosis from an interface snapshot."""
        # 1. Thermal overload check
        if snap.temperature_c is not None and snap.temperature_c >= self.temp_crit_c:
            return TelemetryCorrelationVerdict(
                device=snap.device,
                interface=snap.interface,
                diagnosis=TelemetryDiagnosisType.THERMAL_SHUTDOWN,
                confidence=0.95,
                summary=(
                    f"Transceiver temperature ({snap.temperature_c:.1f}°C) exceeds "
                    f"critical threshold ({self.temp_crit_c:.1f}°C)."
                ),
                recommended_action="Inspect fan trays, airflow, and transceiver thermal rating.",
            )

        # 2. Complete loss of light without gradual CRC buildup -> remote shut or fiber cut
        if (
            snap.rx_power_dbm is not None
            and snap.rx_power_dbm <= self.rx_los_crit_dbm
            and snap.fcs_crc_errors_delta == 0
        ):
            return TelemetryCorrelationVerdict(
                device=snap.device,
                interface=snap.interface,
                diagnosis=TelemetryDiagnosisType.DARK_FIBER_OR_REMOTE_SHUT,
                confidence=0.90,
                summary=(
                    f"Hard Rx LOS ({snap.rx_power_dbm:.1f} dBm) with 0 prior FCS/CRC errors; "
                    "indicates remote port admin-shut, remote reboot, or clean fiber disconnect."
                ),
                recommended_action="Verify remote peer maintenance state before dispatching hands-on fiber tech.",
            )

        # 3. Degraded Rx optical budget or active FCS/CRC bit errors
        if (
            snap.rx_power_dbm is not None and snap.rx_power_dbm <= self.rx_low_warn_dbm
        ) or snap.fcs_crc_errors_delta >= self.crc_storm_threshold:
            rx_str = f"{snap.rx_power_dbm:.1f} dBm" if snap.rx_power_dbm is not None else "N/A"
            return TelemetryCorrelationVerdict(
                device=snap.device,
                interface=snap.interface,
                diagnosis=TelemetryDiagnosisType.OPTICAL_DEGRADATION,
                confidence=0.94,
                summary=(
                    f"Physical layer impairment on {snap.device} {snap.interface}: "
                    f"Rx power={rx_str}, FCS/CRC delta={snap.fcs_crc_errors_delta}."
                ),
                recommended_action="Clean/reseat fiber patch cord, inspect patch panel, or replace SFP/QSFP.",
            )

        # 4. Clean optics & 0 CRC errors, but high output/input discards -> QoS/CoPP congestion
        total_discards = snap.in_discards_delta + snap.out_discards_delta
        if total_discards >= self.discard_congestion_threshold and snap.fcs_crc_errors_delta == 0:
            return TelemetryCorrelationVerdict(
                device=snap.device,
                interface=snap.interface,
                diagnosis=TelemetryDiagnosisType.QOS_CONGESTION_DROP,
                confidence=0.92,
                summary=(
                    f"Optics healthy ({snap.rx_power_dbm or 0.0:.1f} dBm, 0 CRC), but "
                    f"{total_discards} queue discards detected. Control-plane BFD/BGP drops "
                    "are likely caused by microburst buffer exhaustion or CoPP policing."
                ),
                recommended_action="Inspect QoS queue-6/7 strict-priority scheduling for BFD/BGP and CoPP drop counters.",
            )

        return TelemetryCorrelationVerdict(
            device=snap.device,
            interface=snap.interface,
            diagnosis=TelemetryDiagnosisType.HEALTHY_PHYSICAL,
            confidence=0.85,
            summary=f"Physical telemetry within normal operating bounds on {snap.device} {snap.interface}.",
            recommended_action="Focus RCA on control-plane configuration, routing policy, or MTU mismatch.",
        )


class PrometheusTelemetryBridge:
    """Fetches interface metrics from a Prometheus HTTP API endpoint."""

    def __init__(self, base_url: str, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def query_instant(self, promql: str) -> list[dict[str, Any]]:
        params = urllib.parse.urlencode({"query": promql})
        url = f"{self.base_url}/api/v1/query?{params}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload.get("data", {}).get("result", [])
