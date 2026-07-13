"""One-command demo — synthetic multi-vendor syslog with a built-in storyline.

`ai-log-analyzer demo` needs no lab, no devices, no LLM key: it generates a
deterministic incident narrative across six devices and four vendor dialects,
runs the full analysis pipeline on it, and prints the result. With `--serve`
it also starts the web UI with a live syslog feeder, so the Live Tail panel
streams the same story in real time.

The storyline is designed to light up every analysis surface:
  * a flapping access interface on an EOS leaf     → stability engine
  * a BGP session collapse on a Junos spine        → action items + playbooks
  * an NX-OS service crash + PSU failure           → critical hardware/system
  * an SSH brute-force burst on the firewall       → security
  * SR Linux BGP session churn                     → vendor coverage
  * a never-seen "quantum optics" appdaemon shape  → unknown-pattern miner
"""
from __future__ import annotations

import itertools
from collections.abc import Iterator

_DEVICES = {
    "spine-01": "junos",   # MX — BGP collapse
    "spine-02": "nxos",    # Nexus — service crash + PSU
    "leaf-11": "eos",      # Arista — interface flapping
    "leaf-12": "srl",      # SR Linux — BGP churn
    "edge-fw-01": "junos", # SRX — auth failures
    "core-rt-01": "ios",   # IOS-XE — EIGRP + config
}


def _ts(minute: int, second: int = 0) -> str:
    return f"Jan 14 09:{minute:02d}:{second:02d}"


def generate_demo_lines() -> list[str]:
    """Deterministic synthetic syslog — same story every run (~180 lines)."""
    lines: list[str] = []
    add = lines.append

    # Baseline chatter (all healthy)
    for m in range(0, 8):
        add(f"{_ts(m, 5)} core-rt-01 %SYS-5-CONFIG_I: Configured from console by ops on vty0 (198.51.100.7)")
        add(f"{_ts(m, 20)} spine-01 sshd[112{m}]: Accepted publickey for netops from 198.51.100.7 port 5{m}122 ssh2")
        add(f"{_ts(m, 40)} leaf-11 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet12, changed state to up")

    # Act 1 — leaf-11 interface starts flapping (minutes 8-14, 3 full cycles)
    for i, m in enumerate(range(8, 14)):
        state = "down" if i % 2 == 0 else "up"
        add(f"{_ts(m, 10)} leaf-11 Ebra: %LINK-3-UPDOWN: Interface Ethernet49/1, changed state to {state}")

    # Act 2 — spine-01 BGP session collapses under the flap (minutes 12-18)
    for m in range(12, 18):
        add(f"{_ts(m, 30)} spine-01 rpd[1451]: bgp_connect_failed: peer 10.255.1.11 (External AS 65011): hold timer expired")
        add(f"{_ts(m, 45)} spine-01 rpd[1451]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.255.1.11 state Idle")

    # Act 3 — spine-02 platform trouble (minute 15)
    add(f"{_ts(15, 2)} spine-02 %SYSMGR-2-SERVICE_CRASHED: Service \"bgp\" (PID 4321) hasn't caught signal 11")
    add(f"{_ts(15, 8)} spine-02 %PLATFORM-2-PS_FAIL: Power supply 1 failed or shutdown")
    add(f"{_ts(15, 30)} spine-02 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down (Link failure)")

    # Act 4 — brute force against the firewall (minutes 16-19)
    for m in range(16, 20):
        for s in (5, 25, 45):
            add(f"{_ts(m, s)} edge-fw-01 sshd[9911]: authentication failure for root from 203.0.113.66")

    # Act 5 — SR Linux BGP churn on leaf-12 (minutes 18-21)
    for i, m in enumerate(range(18, 22)):
        state = "idle" if i % 2 == 0 else "established"
        add(f"{_ts(m, 15)} leaf-12 sr_bgp_mgr: Peer 10.255.1.1: session state changed from established to {state}")

    # Act 6 — EIGRP wobble + recovery on core (minutes 20-23)
    add(f"{_ts(20, 40)} core-rt-01 %DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 10.0.12.2 (Gi0/1) is down: holding time expired")
    add(f"{_ts(22, 10)} core-rt-01 %DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor 10.0.12.2 (Gi0/1) is up: new adjacency")

    # Act 7 — a message shape no KB rule knows (unknown-pattern miner food)
    for m in range(9, 21, 3):
        add(f"{_ts(m, 55)} spine-01 appdaemon[77]: quantum optics calibration drift {m} exceeded budget on lane {m % 4}")

    # Recovery tail (minutes 22-25)
    add(f"{_ts(23, 5)} leaf-11 Ebra: %LINK-3-UPDOWN: Interface Ethernet49/1, changed state to up")
    add(f"{_ts(23, 30)} spine-01 rpd[1451]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.255.1.11 state Established")
    return lines


def iter_feeder_lines() -> Iterator[str]:
    """Endless replay of the storyline — used by `demo --serve` to keep the
    Live Tail panel busy."""
    return itertools.cycle(generate_demo_lines())


def start_udp_feeder(port: int, interval: float = 0.7) -> None:
    """Daemon thread that pumps storyline lines at the local syslog listener."""
    import socket
    import threading
    import time

    def _run() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for line in iter_feeder_lines():
            try:
                sock.sendto(f"<22>{line}".encode(), ("127.0.0.1", port))
            except OSError:
                break
            time.sleep(interval)

    threading.Thread(target=_run, name="demo-feeder", daemon=True).start()
