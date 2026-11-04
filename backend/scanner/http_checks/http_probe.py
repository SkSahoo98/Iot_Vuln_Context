"""Safe HTTP header probe and deterministic WEB-* findings."""

from __future__ import annotations

import httpx

from scanner.core.findings import make_finding
from scanner.core.models import Evidence, FindingCandidate

RECOMMENDED_HEADERS = (
    "x-content-type-options",
    "content-security-policy",
)


def _url(target: str, port: int, scheme: str) -> str:
    host = f"[{target}]" if ":" in target else target
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    suffix = "" if default_port else f":{port}"
    return f"{scheme}://{host}{suffix}/"


def probe_http(
    target: str,
    port: int,
    scheme: str,
    timeout: float = 5.0,
) -> Evidence:
    """Fetch response headers only; do not follow redirects or read the body."""
    url = _url(target, port, scheme)
    try:
        # Certificate validity is assessed independently by TLS_PROBE. Using
        # verify=False here permits header collection while preserving the
        # verification result as separate, explicit TLS evidence.
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
        ) as client:
            with client.stream("GET", url, headers={"User-Agent": "IoTSecurityLab/1.0"}) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                return Evidence(
                    target=target,
                    port=port,
                    check_type="HTTP_RESPONSE",
                    result="AVAILABLE",
                    evidence_source="HTTP_PROBE",
                    observation={
                        "scheme": scheme,
                        "status_code": response.status_code,
                        "headers": headers,
                        "certificate_verification_delegated_to": "TLS_PROBE"
                        if scheme == "https"
                        else None,
                    },
                )
    except httpx.TimeoutException as exc:
        result = "TIMEOUT"
        error_type = type(exc).__name__
        error = str(exc)[:300]
    except httpx.HTTPError as exc:
        result = "UNAVAILABLE"
        error_type = type(exc).__name__
        error = str(exc)[:300]
    return Evidence(
        target=target,
        port=port,
        check_type="HTTP_RESPONSE",
        result=result,
        evidence_source="HTTP_PROBE",
        observation={
            "scheme": scheme,
            "error_type": error_type,
            "error": error,
        },
    )


def evaluate_http(
    evidence: Evidence,
    *,
    https_available: bool,
) -> list[FindingCandidate]:
    if evidence.result != "AVAILABLE":
        return []

    findings: list[FindingCandidate] = []
    scheme = evidence.observation.get("scheme")
    headers = evidence.observation.get("headers")
    if not isinstance(headers, dict):
        headers = {}

    if scheme == "http" and not https_available:
        findings.append(
            make_finding(
                "WEB-01",
                evidence,
                description=(
                    f"An HTTP response was observed on {evidence.target}:"
                    f"{evidence.port}, while no HTTPS endpoint was observed in "
                    "the limited assessment port set."
                ),
                confidence=0.9,
            )
        )

    missing = [header for header in RECOMMENDED_HEADERS if header not in headers]
    if scheme == "https" and "strict-transport-security" not in headers:
        missing.append("strict-transport-security")
    if missing:
        findings.append(
            make_finding(
                "WEB-02",
                evidence,
                description=(
                    "The observed HTTP response omitted these applicable "
                    f"headers: {', '.join(missing)}."
                ),
                confidence=0.9,
            )
        )

    disclosed = {
        header: str(headers[header])[:200]
        for header in ("server", "x-powered-by")
        if headers.get(header)
    }
    if disclosed:
        findings.append(
            make_finding(
                "WEB-03",
                evidence,
                description=(
                    "The response disclosed server information: "
                    + ", ".join(f"{key}={value}" for key, value in disclosed.items())
                    + ". No CVE inference was performed."
                ),
                confidence=0.95,
            )
        )
    return findings
