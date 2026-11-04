"""
Stable check catalog.

ID convention: <LAYER>-<NN>, with MQTT checks under IOT-MQTT-<NN>.
  NET-*       network / service exposure (evidence: Nmap)
  IOT-MQTT-*  MQTT protocol security (evidence: MQTT probe, TLS probe)
  WEB-*       HTTP security (evidence: HTTP probe)
  TLS-*       TLS service security (evidence: TLS probe)

Severities are fixed per check so results are deterministic and reproducible.
INFO findings are observations and are not risk-scored.
"""

from __future__ import annotations

from dataclasses import dataclass

# Must change whenever a check is added/removed or its detection logic or
# severity changes, so assessments are only compared under the same rules.
CHECK_CATALOG_VERSION = "IoT-CHECKS-v1"


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    finding_type: str
    category: str
    title: str
    severity: str
    remediation: str


_CHECKS = (
    CheckDefinition(
        "NET-01",
        "OPEN_SERVICE",
        "NETWORK",
        "Open TCP service observed",
        "INFO",
        "Confirm the service is required; close or firewall it otherwise.",
    ),
    CheckDefinition(
        "NET-02",
        "EXCESSIVE_ATTACK_SURFACE",
        "NETWORK",
        "Number of open services exceeds the configured threshold",
        "LOW",
        "Disable services that are not required for the device's function.",
    ),
    CheckDefinition(
        "NET-03",
        "TELNET_EXPOSED",
        "NETWORK",
        "Telnet service exposed",
        "HIGH",
        "Disable Telnet and use SSH with key-based authentication if remote "
        "administration is required.",
    ),
    CheckDefinition(
        "NET-04",
        "FTP_EXPOSED",
        "NETWORK",
        "FTP service exposed",
        "MEDIUM",
        "Disable FTP or replace it with SFTP/FTPS restricted to authorized hosts.",
    ),
    CheckDefinition(
        "NET-06",
        "UNEXPECTED_ADMIN_SERVICE",
        "NETWORK",
        "Administrative service reachable",
        "LOW",
        "Verify the administrative service is required and restrict it to "
        "management hosts.",
    ),
    CheckDefinition(
        "IOT-MQTT-01",
        "MQTT_ANONYMOUS_ACCESS",
        "IOT_PROTOCOL",
        "MQTT broker accepted an anonymous connection",
        "HIGH",
        "Set allow_anonymous false, configure a password_file, and enforce "
        "topic ACLs for each client.",
    ),
    CheckDefinition(
        "IOT-MQTT-02",
        "MQTT_WITHOUT_TLS",
        "IOT_PROTOCOL",
        "MQTT accepted over plaintext and no TLS listener was reachable",
        "MEDIUM",
        "Enable an MQTT TLS listener (port 8883) with a valid certificate and "
        "move clients to it.",
    ),
    CheckDefinition(
        "IOT-MQTT-03",
        "MQTT_SERVICE_INFO",
        "IOT_PROTOCOL",
        "MQTT broker version disclosed via $SYS topics",
        "INFO",
        "Restrict $SYS topic access to administrative clients via ACLs.",
    ),
    CheckDefinition(
        "WEB-01",
        "HTTP_PLAINTEXT",
        "WEB",
        "HTTP served in plaintext and no HTTPS service observed",
        "MEDIUM",
        "Serve the interface over HTTPS and redirect plaintext HTTP.",
    ),
    CheckDefinition(
        "WEB-02",
        "HTTP_SECURITY_HEADERS",
        "WEB",
        "Recommended HTTP security headers missing",
        "LOW",
        "Add the missing security headers in the web server configuration.",
    ),
    CheckDefinition(
        "WEB-03",
        "SERVER_INFORMATION_DISCLOSURE",
        "WEB",
        "Server software information disclosed in HTTP headers",
        "LOW",
        "Suppress version details in the Server / X-Powered-By headers.",
    ),
    CheckDefinition(
        "TLS-01",
        "TLS_SERVICE_AVAILABLE",
        "TLS",
        "TLS service reachable",
        "INFO",
        "No action required; certificate and protocol checks are reported "
        "separately.",
    ),
    CheckDefinition(
        "TLS-02",
        "CERTIFICATE_EXPIRED",
        "TLS",
        "TLS certificate has expired",
        "MEDIUM",
        "Renew the certificate and deploy it to the service.",
    ),
    CheckDefinition(
        "TLS-03",
        "OUTDATED_TLS_VERSION",
        "TLS",
        "Outdated TLS protocol version negotiated",
        "MEDIUM",
        "Disable TLS 1.1 and older; allow TLS 1.2 and TLS 1.3 only.",
    ),
    CheckDefinition(
        "TLS-04",
        "CERTIFICATE_NOT_TRUSTED",
        "TLS",
        "TLS certificate could not be verified",
        "LOW",
        "Use a certificate issued by a CA trusted by the clients and matching "
        "the service address.",
    ),
)

CHECKS: dict[str, CheckDefinition] = {check.check_id: check for check in _CHECKS}


def get_check(check_id: str) -> CheckDefinition:
    return CHECKS[check_id]
