"""Active TLS handshake probe and deterministic TLS findings."""

from __future__ import annotations

import socket
import ssl
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.core.findings import make_finding
from scanner.core.models import Evidence, FindingCandidate


def _decode_certificate(der_certificate: bytes) -> dict[str, Any]:
    """Decode an observed certificate using Python's bundled OpenSSL helper."""
    pem = ssl.DER_cert_to_PEM_cert(der_certificate)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".pem",
            encoding="ascii",
            delete=False,
        ) as handle:
            handle.write(pem)
            temporary_path = handle.name
        # Python does not expose a public DER-to-dict decoder. This helper is
        # part of CPython's ssl extension and avoids adding a dependency solely
        # to read dates/subject from an already observed certificate.
        return ssl._ssl._test_decode_cert(temporary_path)  # type: ignore[attr-defined]
    finally:
        if temporary_path:
            Path(temporary_path).unlink(missing_ok=True)


def _name_to_text(name: Any) -> str | None:
    if not isinstance(name, (tuple, list)):
        return None
    parts: list[str] = []
    for rdn in name:
        if not isinstance(rdn, (tuple, list)):
            continue
        for item in rdn:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                parts.append(f"{item[0]}={item[1]}")
    return ", ".join(parts) or None


def probe_tls(target: str, port: int, timeout: float = 5.0) -> Evidence:
    """Attempt an unverified handshake, then independently verify trust."""
    observation: dict[str, Any] = {}
    try:
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with unverified.wrap_socket(raw, server_hostname=target) as secured:
                der = secured.getpeercert(binary_form=True)
                observation.update(
                    {
                        "tls_version": secured.version(),
                        "cipher": secured.cipher()[0] if secured.cipher() else None,
                        "certificate_present": bool(der),
                    }
                )
                if der:
                    decoded = _decode_certificate(der)
                    observation.update(
                        {
                            "certificate_subject": _name_to_text(
                                decoded.get("subject")
                            ),
                            "certificate_issuer": _name_to_text(decoded.get("issuer")),
                            "certificate_not_before": decoded.get("notBefore"),
                            "certificate_not_after": decoded.get("notAfter"),
                            "certificate_serial_number": decoded.get("serialNumber"),
                        }
                    )
    except (TimeoutError, socket.timeout) as exc:
        return Evidence(
            target=target,
            port=port,
            check_type="TLS_HANDSHAKE",
            result="TIMEOUT",
            evidence_source="TLS_PROBE",
            observation={"error_type": type(exc).__name__},
        )
    except ConnectionRefusedError as exc:
        return Evidence(
            target=target,
            port=port,
            check_type="TLS_HANDSHAKE",
            result="REFUSED",
            evidence_source="TLS_PROBE",
            observation={"error_type": type(exc).__name__},
        )
    except (ssl.SSLError, OSError, ValueError) as exc:
        return Evidence(
            target=target,
            port=port,
            check_type="TLS_HANDSHAKE",
            result="UNAVAILABLE",
            evidence_source="TLS_PROBE",
            observation={
                "error_type": type(exc).__name__,
                "error": str(exc)[:300],
            },
        )

    try:
        verified = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with verified.wrap_socket(raw, server_hostname=target):
                observation["certificate_verified"] = True
                observation["verification_error"] = None
    except ssl.SSLCertVerificationError as exc:
        observation["certificate_verified"] = False
        observation["verification_error"] = str(exc)[:300]
        observation["verification_code"] = exc.verify_code
    except (ssl.SSLError, OSError, TimeoutError) as exc:
        observation["certificate_verified"] = False
        observation["verification_error"] = str(exc)[:300]

    return Evidence(
        target=target,
        port=port,
        check_type="TLS_HANDSHAKE",
        result="AVAILABLE",
        evidence_source="TLS_PROBE",
        observation=observation,
    )


def _certificate_expired(observation: dict[str, Any]) -> bool:
    not_after = observation.get("certificate_not_after")
    if not isinstance(not_after, str):
        return False
    try:
        expiry = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_after),
            tz=UTC,
        )
    except (ValueError, OverflowError):
        return False
    return expiry < datetime.now(UTC)


def evaluate_tls(evidence: Evidence) -> list[FindingCandidate]:
    """Create findings only from an available, observed TLS handshake."""
    if evidence.result != "AVAILABLE":
        return []

    findings = [
        make_finding(
            "TLS-01",
            evidence,
            description=(
                f"TLS handshake succeeded on {evidence.target}:{evidence.port}; "
                f"negotiated {evidence.observation.get('tls_version') or 'unknown'}."
            ),
            confidence=0.99,
        )
    ]

    if _certificate_expired(evidence.observation):
        findings.append(
            make_finding(
                "TLS-02",
                evidence,
                description=(
                    "The observed TLS certificate expired at "
                    f"{evidence.observation.get('certificate_not_after')}."
                ),
                confidence=0.99,
            )
        )

    version = evidence.observation.get("tls_version")
    if version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        findings.append(
            make_finding(
                "TLS-03",
                evidence,
                description=f"The active handshake negotiated {version}.",
                confidence=0.99,
            )
        )

    if evidence.observation.get("certificate_verified") is False:
        findings.append(
            make_finding(
                "TLS-04",
                evidence,
                description=(
                    "The certificate could not be verified by the host trust "
                    "store: "
                    f"{evidence.observation.get('verification_error') or 'unknown'}."
                ),
                confidence=0.95,
            )
        )
    return findings
