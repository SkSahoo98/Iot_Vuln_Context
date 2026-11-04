"""
Nmap TCP connect scan of a single allowlisted target.

Runs: nmap -sT -Pn -sV -T4 --max-retries 1 --host-timeout <N>s -p <ports> -oX - <ip>

The command is built as an argument list (never a shell string). The target
must already be validated as an allowlisted IP literal by the caller.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from typing import Any

from scanner.core.models import Evidence

logger = logging.getLogger(__name__)


class NmapError(Exception):
    """Nmap could not produce a usable result."""


class NmapParseError(NmapError):
    """Nmap XML output could not be parsed."""


@dataclass
class PortObservation:
    port: int
    protocol: str
    state: str
    reason: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NmapScanResult:
    target: str
    host_state: str | None
    ports: list[PortObservation] = field(default_factory=list)
    # Ports Nmap collapsed into <extraports>, e.g. {"filtered": 13}
    extraports: dict[str, int] = field(default_factory=dict)
    nmap_version: str | None = None
    args: str | None = None
    elapsed_seconds: float | None = None

    @property
    def open_ports(self) -> list[PortObservation]:
        return [p for p in self.ports if p.state == "open"]

    def state_counts(self) -> dict[str, int]:
        counts: dict[str, int] = dict(self.extraports)
        for p in self.ports:
            counts[p.state] = counts.get(p.state, 0) + 1
        return counts

    @property
    def target_responded(self) -> bool:
        """True if any port answered (open, closed or unfiltered).

        With -Pn, Nmap marks the host "up" without probing it, so a host that
        is offline shows every port as filtered. Only an actual port response
        proves reachability.
        """
        counts = self.state_counts()
        return any(counts.get(state, 0) > 0 for state in ("open", "closed", "unfiltered"))

    def port(self, number: int) -> PortObservation | None:
        return next((p for p in self.ports if p.port == number), None)


def parse_port_list(spec: str) -> list[int]:
    ports: list[int] = []
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue
        if not item.isdigit():
            raise ValueError(f"Invalid port in port list: {item!r}")
        value = int(item)
        if not 1 <= value <= 65535:
            raise ValueError(f"Port out of range: {value}")
        if value not in ports:
            ports.append(value)
    if not ports:
        raise ValueError("Port list is empty")
    return ports


def build_nmap_command(
    nmap_executable: str,
    target: str,
    ports: list[int],
    host_timeout_seconds: int,
) -> list[str]:
    # Defence in depth: only an IP literal can reach the command line.
    ip_address(target)
    return [
        nmap_executable,
        "-sT",
        "-Pn",
        "-sV",
        "-T4",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{int(host_timeout_seconds)}s",
        "-p",
        ",".join(str(p) for p in ports),
        "-oX",
        "-",
        target,
    ]


def parse_nmap_xml(xml_text: str, target: str) -> NmapScanResult:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapParseError(f"Malformed Nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError(f"Unexpected Nmap XML root element: {root.tag}")

    result = NmapScanResult(
        target=target,
        host_state=None,
        nmap_version=root.get("version"),
        args=root.get("args"),
    )

    finished = root.find("runstats/finished")
    if finished is not None and finished.get("elapsed"):
        try:
            result.elapsed_seconds = float(finished.get("elapsed", ""))
        except ValueError:
            result.elapsed_seconds = None

    host = root.find("host")
    if host is None:
        return result

    status = host.find("status")
    result.host_state = status.get("state") if status is not None else None

    for extra in host.findall("ports/extraports"):
        state = extra.get("state")
        count = extra.get("count")
        if state and count and count.isdigit():
            result.extraports[state] = result.extraports.get(state, 0) + int(count)

    for port_el in host.findall("ports/port"):
        portid = port_el.get("portid", "")
        if not portid.isdigit():
            raise NmapParseError(f"Invalid portid in Nmap XML: {portid!r}")
        state_el = port_el.find("state")
        service_el = port_el.find("service")
        result.ports.append(
            PortObservation(
                port=int(portid),
                protocol=port_el.get("protocol", "tcp"),
                state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                reason=state_el.get("reason") if state_el is not None else None,
                service_name=service_el.get("name") if service_el is not None else None,
                product=service_el.get("product") if service_el is not None else None,
                version=service_el.get("version") if service_el is not None else None,
                extrainfo=service_el.get("extrainfo") if service_el is not None else None,
                tunnel=service_el.get("tunnel") if service_el is not None else None,
            )
        )

    return result


def run_nmap(
    target: str,
    ports: list[int],
    *,
    nmap_path: str = "nmap",
    timeout_seconds: int = 180,
) -> NmapScanResult:
    executable = shutil.which(nmap_path)
    if executable is None:
        raise NmapError(f"Nmap executable not found: {nmap_path}")

    command = build_nmap_command(executable, target, ports, timeout_seconds)
    logger.info("Running Nmap against %s (%d ports)", target, len(ports))

    try:
        completed = subprocess.run(  # noqa: S603 - argument list, no shell
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 30,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"Nmap timed out after {timeout_seconds + 30}s") from exc
    except OSError as exc:
        raise NmapError(f"Nmap could not be executed: {exc}") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()[-500:]
        raise NmapError(f"Nmap exited with code {completed.returncode}: {stderr}")

    return parse_nmap_xml(completed.stdout, target)


def build_nmap_evidence(
    scan: NmapScanResult,
) -> tuple[Evidence, dict[int, Evidence]]:
    """Return (scan summary evidence, per-open-port evidence)."""
    counts = scan.state_counts()
    summary = Evidence(
        target=scan.target,
        check_type="NMAP_SCAN",
        result="RESPONDED" if scan.target_responded else "NO_RESPONSE",
        evidence_source="NMAP",
        observation={
            "nmap_version": scan.nmap_version,
            "args": scan.args,
            "host_state": scan.host_state,
            "state_counts": counts,
            "open_ports": [p.port for p in scan.open_ports],
            "listed_ports": [p.to_dict() for p in scan.ports],
            "elapsed_seconds": scan.elapsed_seconds,
        },
    )
    per_port = {
        p.port: Evidence(
            target=scan.target,
            port=p.port,
            check_type="NMAP_PORT",
            result="OPEN",
            evidence_source="NMAP",
            observation=p.to_dict(),
        )
        for p in scan.open_ports
    }
    return summary, per_port
