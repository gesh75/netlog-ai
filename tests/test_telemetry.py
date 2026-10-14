"""Unit tests for optical DOM/DDM and interface counter telemetry correlation."""

from __future__ import annotations

import pytest

from ai_log_analyzer.sources.telemetry import (
    InterfaceTelemetrySnapshot,
    TelemetryCorrelator,
    TelemetryDiagnosisType,
)


@pytest.mark.unit
def test_detects_degraded_optical_transceiver() -> None:
    correlator = TelemetryCorrelator()
    snap = InterfaceTelemetrySnapshot(
        device="leaf1",
        interface="Ethernet1/1",
        rx_power_dbm=-19.4,
        tx_power_dbm=-1.2,
        temperature_c=46.0,
        fcs_crc_errors_delta=342,
    )
    verdict = correlator.evaluate_snapshot(snap)
    assert verdict.diagnosis == TelemetryDiagnosisType.OPTICAL_DEGRADATION
    assert verdict.confidence >= 0.90
    assert "Clean/reseat fiber" in verdict.recommended_action


@pytest.mark.unit
def test_distinguishes_qos_congestion_from_physical_fault() -> None:
    correlator = TelemetryCorrelator()
    snap = InterfaceTelemetrySnapshot(
        device="spine1",
        interface="xe-0/0/1",
        rx_power_dbm=-2.3,
        tx_power_dbm=-1.8,
        temperature_c=42.0,
        fcs_crc_errors_delta=0,
        out_discards_delta=18400,
    )
    verdict = correlator.evaluate_snapshot(snap)
    assert verdict.diagnosis == TelemetryDiagnosisType.QOS_CONGESTION_DROP
    assert "CoPP" in verdict.summary
    assert "queue-6/7" in verdict.recommended_action


@pytest.mark.unit
def test_detects_clean_remote_shutdown_vs_dirty_fiber() -> None:
    correlator = TelemetryCorrelator()
    snap = InterfaceTelemetrySnapshot(
        device="de-fra-core-01",
        interface="et-0/0/0",
        rx_power_dbm=-40.0,
        fcs_crc_errors_delta=0,
    )
    verdict = correlator.evaluate_snapshot(snap)
    assert verdict.diagnosis == TelemetryDiagnosisType.DARK_FIBER_OR_REMOTE_SHUT
