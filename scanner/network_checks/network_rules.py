"""Deterministic network exposure rules (NET-*) over Nmap evidence."""

from __future__ import annotations

from scanner.core.findings import make_finding
from scanner.core.models import Evidence, FindingCandidate
from scanner.network_checks.nmap_scanner import NmapScanResult, PortObservation

TELNET_PORT = 23
FTP_PORT = 21
HTTP_PORTS = frozenset({80, 8080})
HTTPS_PORTS = frozenset({443, 8443})


def _service_label(port: PortObservation) -> str:
    parts = [p for p in (port.service_name, port.product, port.version) if p]
    return " ".join(parts) if parts else "unidentified"


def _is_service(port: PortObservation, name: str, default_port: int) -> bool:
    return port.port == default_port or (port.service_name or "").lower() == name


def evaluate_network(
    scan: NmapScanResult,
    summary_evidence: Evidence,
    port_evidence: dict[int, Evidence],
    *,
    max_open_services: int,
    admin_service_ports: list[int],
) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    open_ports = scan.open_ports

    for port in open_ports:
        evidence = port_evidence[port.port]
        findings.append(
            make_finding(
                "NET-01",
                evidence,
                description=(
                    f"Nmap observed TCP port {port.port} open "
                    f"(service: {_service_label(port)})."
                ),
                confidence=0.95,
            )
        )

        if _is_service(port, "telnet", TELNET_PORT):
            findings.append(
                make_finding(
                    "NET-03",
                    evidence,
                    description=(
                        f"Nmap observed Telnet reachable on TCP port {port.port} "
                        f"(service: {_service_label(port)}). Telnet transmits "
                        "credentials and session data in plaintext."
                    ),
                    confidence=0.9,
                )
            )
        elif _is_service(port, "ftp", FTP_PORT):
            findings.append(
                make_finding(
                    "NET-04",
                    evidence,
                    description=(
                        f"Nmap observed FTP reachable on TCP port {port.port} "
                        f"(service: {_service_label(port)})."
                    ),
                    confidence=0.9,
                )
            )
        elif port.port in admin_service_ports:
            findings.append(
                make_finding(
                    "NET-06",
                    evidence,
                    description=(
                        f"Administrative service reachable on TCP port {port.port} "
                        f"(service: {_service_label(port)}). Port {port.port} is "
                        "listed in ASSESSMENT_ADMIN_SERVICE_PORTS."
                    ),
                    confidence=0.85,
                )
            )

    if len(open_ports) > max_open_services:
        findings.append(
            make_finding(
                "NET-02",
                summary_evidence,
                description=(
                    f"{len(open_ports)} open TCP services observed "
                    f"({', '.join(str(p.port) for p in open_ports)}); the "
                    f"configured threshold is {max_open_services}."
                ),
                confidence=0.9,
            )
        )

    return findings


def http_endpoints(scan: NmapScanResult) -> list[tuple[int, str]]:
    """Open ports that should receive HTTP checks, as (port, scheme)."""
    endpoints: list[tuple[int, str]] = []
    for port in scan.open_ports:
        name = (port.service_name or "").lower()
        is_tls = port.tunnel == "ssl" or name == "https" or port.port in HTTPS_PORTS
        is_http = "http" in name or port.port in HTTP_PORTS or port.port in HTTPS_PORTS
        if is_http:
            endpoints.append((port.port, "https" if is_tls else "http"))
    return endpoints


def tls_endpoints(scan: NmapScanResult, mqtt_tls_port: int) -> list[int]:
    """Open ports that should receive TLS checks."""
    ports: list[int] = []
    for port in scan.open_ports:
        name = (port.service_name or "").lower()
        if (
            port.tunnel == "ssl"
            or name in {"https", "ssl", "secure-mqtt"}
            or port.port in HTTPS_PORTS
            or port.port == mqtt_tls_port
        ):
            ports.append(port.port)
    return ports
