"""
Check coverage recorded from what an assessment actually executed.

Coverage is derived from probe results and rule preconditions, never from the
findings produced. Statuses:
  EVALUATED       the rule ran on a usable observation; absence of a finding
                  means the condition was not observed.
  NOT_APPLICABLE  the rule's precondition was observed to be absent (e.g. no
                  MQTT listener, no HTTP endpoint).
  NOT_EVALUATED   the check applied or may have applied but could not be
                  determined (probe timeout/error, discovery failure, run
                  failure). Absence of a finding means nothing.
"""

from __future__ import annotations

import ssl
from datetime import UTC, datetime

from scanner.core.catalog import CHECKS
from scanner.core.models import Evidence

EVALUATED = "EVALUATED"
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_EVALUATED = "NOT_EVALUATED"

# Lower rank wins when the same check/port is recorded twice.
_RANK = {NOT_EVALUATED: 0, NOT_APPLICABLE: 1, EVALUATED: 2}

NETWORK_PREFIX = "NET-"
MQTT_PREFIX = "IOT-MQTT-"
WEB_PREFIX = "WEB-"
TLS_PREFIX = "TLS-"


def family_checks(prefix: str) -> list[str]:
    return sorted(check_id for check_id in CHECKS if check_id.startswith(prefix))


class CheckCoverage:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, int | None], str] = {}

    def record(self, statuses: dict[str, str], port: int | None) -> None:
        for check_id, status in statuses.items():
            if check_id not in CHECKS or status not in _RANK:
                raise ValueError(f"Invalid coverage entry: {check_id}={status}")
            key = (check_id, port)
            current = self._entries.get(key)
            if current is None or _RANK[status] < _RANK[current]:
                self._entries[key] = status

    def record_family(self, prefix: str, status: str, port: int | None) -> None:
        self.record({check_id: status for check_id in family_checks(prefix)}, port)

    def to_metadata(self) -> list[dict[str, object]]:
        entries = dict(self._entries)
        recorded = {check_id for check_id, _ in entries}
        for check_id in CHECKS:
            if check_id not in recorded:
                entries[(check_id, None)] = NOT_EVALUATED
        return [
            {"check_id": check_id, "port": port, "status": status}
            for (check_id, port), status in sorted(
                entries.items(),
                key=lambda item: (item[0][0], -1 if item[0][1] is None else item[0][1]),
            )
        ]


def mqtt_coverage(
    anonymous_evidence: Evidence,
    tls_evidence: Evidence,
) -> dict[str, str]:
    """Mirror the preconditions of scanner.mqtt_checks.mqtt_rules.evaluate_mqtt."""
    result = anonymous_evidence.result
    if result == "ACCEPTED":
        sys_checked = anonymous_evidence.observation.get("sys_topic_checked") is True
        tls_determined = tls_evidence.result in {
            "AVAILABLE",
            "REFUSED",
            "TIMEOUT",
            "UNAVAILABLE",
        }
        return {
            "IOT-MQTT-01": EVALUATED,
            "IOT-MQTT-02": EVALUATED if tls_determined else NOT_EVALUATED,
            "IOT-MQTT-03": EVALUATED if sys_checked else NOT_EVALUATED,
        }
    if result == "REJECTED":
        return {
            "IOT-MQTT-01": EVALUATED,
            "IOT-MQTT-02": NOT_APPLICABLE,
            "IOT-MQTT-03": NOT_APPLICABLE,
        }
    return {check_id: NOT_EVALUATED for check_id in family_checks(MQTT_PREFIX)}


def http_coverage(evidence: Evidence) -> dict[str, str]:
    """Mirror the preconditions of scanner.http_checks.http_probe.evaluate_http."""
    if evidence.result != "AVAILABLE":
        return {check_id: NOT_EVALUATED for check_id in family_checks(WEB_PREFIX)}
    return {
        "WEB-01": EVALUATED
        if evidence.observation.get("scheme") == "http"
        else NOT_APPLICABLE,
        "WEB-02": EVALUATED,
        "WEB-03": EVALUATED,
    }


def _certificate_expiry_parseable(not_after: object) -> bool:
    if not isinstance(not_after, str):
        return False
    try:
        datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)
    except (ValueError, OverflowError):
        return False
    return True


def tls_coverage(evidence: Evidence) -> dict[str, str]:
    """Mirror the preconditions of scanner.tls_checks.tls_probe.evaluate_tls."""
    if evidence.result != "AVAILABLE":
        return {check_id: NOT_EVALUATED for check_id in family_checks(TLS_PREFIX)}
    observation = evidence.observation
    version = observation.get("tls_version")
    return {
        "TLS-01": EVALUATED,
        "TLS-02": EVALUATED
        if _certificate_expiry_parseable(observation.get("certificate_not_after"))
        else NOT_EVALUATED,
        "TLS-03": EVALUATED
        if isinstance(version, str) and version
        else NOT_EVALUATED,
        "TLS-04": EVALUATED
        if isinstance(observation.get("certificate_verified"), bool)
        else NOT_EVALUATED,
    }
