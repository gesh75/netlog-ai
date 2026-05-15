"""DCN_Network_Tool adapter — bridges to the SSH proxy at localhost:5757.

The network tool exposes:
  POST /api/run       — body {hostname, raw} → SSH-exec output
  GET  /api/devices   — list of lab devices
This adapter wraps that with a small typed interface so the analyzer can run
CLI commands live against the lab containers.

Includes a `docker exec` fallback for FRR lab containers — used when the
DCN_Network_Tool SSH proxy is unavailable or has a config issue (e.g. missing
SSH key path).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

import requests

DCN_TOOL_URL = os.environ.get("DCN_TOOL_URL", "http://localhost:5757")
DOCKER_EXEC_FALLBACK = os.environ.get("DOCKER_EXEC_FALLBACK", "true").lower() == "true"


@dataclass
class CommandResult:
    ok: bool
    hostname: str
    command: str
    output: str
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "hostname": self.hostname,
            "command": self.command,
            "output": self.output,
            "error": self.error,
        }


def is_available(timeout: float = 2.0) -> bool:
    """Probe the DCN_Network_Tool — returns True if the backend is reachable."""
    try:
        r = requests.get(f"{DCN_TOOL_URL.rstrip('/')}/api/devices", timeout=timeout)
        return r.status_code == 200
    except requests.RequestException:
        return False


def list_devices(timeout: float = 5.0) -> list[dict]:
    """Return the device inventory exposed by the network tool."""
    try:
        r = requests.get(f"{DCN_TOOL_URL.rstrip('/')}/api/devices", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            # Network-tool returns either a list or {devices: [...]}
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("devices", data.get("data", []))
    except requests.RequestException:
        pass
    return []


def run_command(hostname: str, command: str, timeout: float = 30.0) -> CommandResult:
    """SSH-execute a command on a lab device. Returns CommandResult."""
    if not command.strip():
        return CommandResult(ok=False, hostname=hostname, command=command,
                             output="", error="Empty command")
    try:
        r = requests.post(
            f"{DCN_TOOL_URL.rstrip('/')}/api/run",
            json={"hostname": hostname, "raw": command},
            timeout=timeout,
        )
    except requests.Timeout:
        return CommandResult(ok=False, hostname=hostname, command=command,
                             output="", error=f"Timeout after {timeout}s")
    except requests.RequestException as e:
        return CommandResult(ok=False, hostname=hostname, command=command,
                             output="", error=f"Network tool unreachable: {e}")

    if r.status_code != 200:
        return CommandResult(ok=False, hostname=hostname, command=command,
                             output="", error=f"HTTP {r.status_code}: {r.text[:200]}")

    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if not isinstance(data, dict):
        return CommandResult(ok=False, hostname=hostname, command=command,
                             output=str(data)[:5000], error="Unexpected response format")

    output = data.get("output", data.get("stdout", ""))
    error = data.get("error", data.get("stderr", ""))
    ok = bool(data.get("ok", not error))

    return CommandResult(
        ok=ok,
        hostname=hostname,
        command=command,
        output=str(output)[:20000],
        error=str(error)[:2000] if error else "",
    )


def fetch_running_config(hostname: str, platform: str = "frr", timeout: float = 30.0) -> Optional[str]:
    """Fetch the running-config for a device.

    Strategy:
      1. Try the DCN_Network_Tool SSH proxy at :5757
      2. If platform is FRR and (1) fails, fall back to `docker exec <container> vtysh ...`
    """
    cmd_map = {
        "frr":   "vtysh -c 'show running-config'",
        "junos": "show configuration | display set | no-more",
        "eos":   "show running-config",
    }
    cmd = cmd_map.get(platform.lower(), cmd_map["frr"])

    if is_available(timeout=1.0):
        result = run_command(hostname, cmd, timeout=timeout)
        if result.ok and result.output:
            return result.output

    if platform.lower() == "frr" and DOCKER_EXEC_FALLBACK:
        return _docker_running_config(hostname, timeout=timeout)
    return None


def _docker_running_config(container: str, timeout: float = 30.0) -> Optional[str]:
    """Pull FRR running-config directly from the container — no SSH needed.

    Uses subprocess.run with a list argument (no shell), so the container
    name and command parts are passed as argv — no injection surface.
    """
    if not shutil.which("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "vtysh", "-c", "show running-config"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    out = (proc.stdout or "").strip()
    if proc.returncode != 0 and not out:
        return None
    return out or None


def container_run(container: str, command: list[str], timeout: float = 30.0) -> CommandResult:
    """Run a command inside a docker container directly. Bypasses DCN_Network_Tool.

    `command` is a list of argv tokens (no shell). Safe by construction.
    """
    if not shutil.which("docker"):
        return CommandResult(ok=False, hostname=container, command=" ".join(command),
                             output="", error="docker CLI not found")
    cmd_str = " ".join(command)
    try:
        proc = subprocess.run(
            ["docker", "exec", container, *command],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(ok=False, hostname=container, command=cmd_str,
                             output="", error=f"Timeout after {timeout}s")
    return CommandResult(
        ok=(proc.returncode == 0),
        hostname=container,
        command=cmd_str,
        output=(proc.stdout or "")[:20000],
        error=(proc.stderr or "")[:2000] if proc.returncode != 0 else "",
    )
