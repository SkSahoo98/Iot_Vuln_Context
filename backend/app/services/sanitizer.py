"""Assessment data sanitization and strict validation engine for secure publishing.

This module provides deterministic sanitization and multi-layer validation
to ensure that local laboratory assessment data transferred to production (Neon)
contains NO private IP addresses, internal filesystem paths, raw execution arguments,
credentials, or broken relational references.
"""

from __future__ import annotations

import re
from copy import deepcopy
from decimal import Decimal
from typing import Any
from uuid import UUID

# RFC 1918 and loopback private IPv4 patterns
# 10.0.0.0 - 10.255.255.255
# 172.16.0.0 - 172.31.255.255
# 192.168.0.0 - 192.168.255.255
# 127.0.0.0 - 127.255.255.255
RFC1918_IPV4_REGEX = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# Windows drive paths (e.g. C:\... or C:/...) and standard Linux root paths
WINDOWS_PATH_REGEX = re.compile(r"[A-Za-z]:[\\/][^'\"\s<>]+", re.IGNORECASE)
LINUX_SYSTEM_PATH_REGEX = re.compile(
    r"(?:^|[\s\"'])(?:/(?:home|usr|etc|var|tmp|opt|root|bin|sbin)[^\s\"']*)",
    re.IGNORECASE,
)

# Sensitive keys that must be completely stripped from JSONB payloads
SENSITIVE_KEY_REGEX = re.compile(
    r"(?i)(password|passwd|secret|token|api_key|auth|credential|conninfo|connection_string|private_key)"
)

# Allowed severities and statuses
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_STATUSES = {"RUNNING", "COMPLETE", "INCOMPLETE", "FAILED"}
VALID_RISK_LEVELS = {"INFO", "LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}

# Canonical mapping for local laboratory targets to cloud-safe logical identifiers
TARGET_MAP = {
    "10.32.252.85": "lab-mqtt-broker",
    "10.32.252.105": "lab-esp32-01",
    "10.32.252.57": "lab-esp32-02",
    "127.0.0.1": "lab-loopback",
    "localhost": "lab-loopback",
}


class SanitizationError(ValueError):
    """Raised when data fails sanitization invariants or validation checks."""


def sanitize_text(text: str | None, target_replacement: str = "lab-mqtt-broker") -> str | None:
    """Sanitize a string by replacing private IPs, stripping paths, and masking args."""
    if text is None:
        return None

    result = text

    # 1. Replace known lab target IPs with logical identifiers
    for ip, logical_name in TARGET_MAP.items():
        result = result.replace(ip, logical_name)

    # 2. Replace any remaining RFC1918 IPs with generic target placeholder
    result = RFC1918_IPV4_REGEX.sub(target_replacement, result)

    # 3. Replace Windows filesystem paths with generic command/path indicator
    def _clean_win_path(m: re.Match) -> str:
        matched = m.group(0)
        lower = matched.lower()
        if "nmap" in lower:
            return "nmap"
        if "python" in lower:
            return "python"
        return "[sanitized-path]"

    result = WINDOWS_PATH_REGEX.sub(_clean_win_path, result)

    # 4. Replace Linux filesystem paths
    def _clean_linux_path(m: re.Match) -> str:
        matched = m.group(0).strip()
        lower = matched.lower()
        if "nmap" in lower:
            return " nmap"
        if "python" in lower:
            return " python"
        return " [sanitized-path]"

    result = LINUX_SYSTEM_PATH_REGEX.sub(_clean_linux_path, result)

    return result


def sanitize_jsonb(
    data: Any,
    target_replacement: str = "lab-mqtt-broker",
) -> Any:
    """Recursively sanitize JSONB-compatible structures (dict, list, str, primitives).

    Strips sensitive keys, replaces private IPs, and scrubs filesystem paths.
    """
    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            # Drop any key matching sensitive patterns
            if SENSITIVE_KEY_REGEX.search(k):
                continue

            # Special handling for Nmap command-line args in observation
            if k == "args" and isinstance(v, str):
                cleaned[k] = "nmap -sT -Pn -sV -T4 -p 21,22,23,25,53,80,110,139,443,445,554,1883,8080,8443,8883 [sanitized-target]"
                continue

            cleaned[k] = sanitize_jsonb(v, target_replacement=target_replacement)
        return cleaned

    if isinstance(data, list):
        return [sanitize_jsonb(item, target_replacement=target_replacement) for item in data]

    if isinstance(data, str):
        return sanitize_text(data, target_replacement=target_replacement)

    if isinstance(data, Decimal):
        return float(data)

    if isinstance(data, UUID):
        return str(data)

    return data


def resolve_canonical_target(raw_target: str | None, default_replacement: str = "lab-mqtt-broker") -> str:
    """Resolve a raw target string into a safe logical identifier."""
    if not raw_target:
        return default_replacement
    target_str = str(raw_target).strip()
    if target_str in TARGET_MAP:
        return TARGET_MAP[target_str]
    if target_str in ("AUTHORIZED_IOT", "ENVIRONMENT"):
        return target_str
    if RFC1918_IPV4_REGEX.search(target_str):
        return default_replacement
    return target_str


def sanitize_assessment_record(
    run: dict[str, Any],
    evidence: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    risks: list[dict[str, Any]],
    canonical_target: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Sanitize the complete assessment dataset in memory before outbound publication."""
    clean_run = deepcopy(run)
    clean_evidence = [deepcopy(e) for e in evidence]
    clean_findings = [deepcopy(f) for f in findings]
    clean_risks = [deepcopy(r) for r in risks]

    target_alias = canonical_target or resolve_canonical_target(clean_run.get("target"))

    # 1. Sanitize Run Record
    clean_run["target"] = target_alias
    raw_meta = clean_run.get("metadata", {}) or {}
    clean_meta = sanitize_jsonb(raw_meta, target_replacement=target_alias)
    clean_meta["published_from"] = "local_cybersecurity_lab"
    clean_meta["is_historical"] = True
    clean_meta["sanitization_version"] = "1.0"
    clean_run["metadata"] = clean_meta
    clean_run["error_summary"] = sanitize_text(clean_run.get("error_summary"), target_replacement=target_alias)

    # 2. Sanitize Evidence Records
    for ev in clean_evidence:
        ev_target = resolve_canonical_target(ev.get("target"), default_replacement=target_alias)
        ev["target"] = ev_target
        ev["observation"] = sanitize_jsonb(ev.get("observation", {}) or {}, target_replacement=ev_target)

    # 3. Sanitize Findings Records
    for f in clean_findings:
        f_target = resolve_canonical_target(f.get("target"), default_replacement=target_alias)
        f["target"] = f_target
        f["title"] = sanitize_text(f.get("title"), target_replacement=f_target)
        f["description"] = sanitize_text(f.get("description"), target_replacement=f_target)
        f["remediation"] = sanitize_text(f.get("remediation"), target_replacement=f_target)

    # 4. Sanitize Risk Snapshots
    for r in clean_risks:
        r["factor_contributions"] = sanitize_jsonb(r.get("factor_contributions", {}) or {}, target_replacement=target_alias)
        r["context_inputs"] = sanitize_jsonb(r.get("context_inputs", {}) or {}, target_replacement=target_alias)

    return clean_run, clean_evidence, clean_findings, clean_risks


def validate_sanitized_data(
    run: dict[str, Any],
    evidence: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    risks: list[dict[str, Any]],
) -> list[str]:
    """Perform recursive and structured validation against the sanitized assessment data.

    Returns a list of violations (empty list means 100% valid).
    """
    violations: list[str] = []

    run_id = str(run.get("id"))
    if not run_id:
        violations.append("Assessment run is missing an 'id'.")

    # Invariant: Run status must be COMPLETE for publishing
    if run.get("status") != "COMPLETE":
        violations.append(f"Assessment status is '{run.get('status')}', expected 'COMPLETE'.")

    if run.get("target") in TARGET_MAP or RFC1918_IPV4_REGEX.search(str(run.get("target"))):
        violations.append(f"Assessment run target contains un-sanitized IP: '{run.get('target')}'.")

    # Check timestamps
    if not run.get("started_at") or not run.get("completed_at"):
        violations.append("Assessment run must have valid started_at and completed_at timestamps.")

    evidence_ids: set[str] = set()
    for i, ev in enumerate(evidence):
        ev_id = str(ev.get("id"))
        evidence_ids.add(ev_id)

        if str(ev.get("assessment_id")) != run_id:
            violations.append(f"Evidence {ev_id} assessment_id does not match run_id {run_id}.")

        if RFC1918_IPV4_REGEX.search(str(ev.get("target"))):
            violations.append(f"Evidence {ev_id} target contains private IP: {ev.get('target')}.")

        # Check port range
        port = ev.get("port")
        if port is not None and not (1 <= int(port) <= 65535):
            violations.append(f"Evidence {ev_id} has invalid port: {port}.")

    finding_ids: set[str] = set()
    for i, f in enumerate(findings):
        f_id = str(f.get("id"))
        finding_ids.add(f_id)

        if str(f.get("assessment_id")) != run_id:
            violations.append(f"Finding {f_id} assessment_id does not match run_id {run_id}.")

        if f.get("severity") not in VALID_SEVERITIES:
            violations.append(f"Finding {f_id} has invalid severity: {f.get('severity')}.")

        ev_ref = str(f.get("evidence_reference")) if f.get("evidence_reference") else None
        if ev_ref and ev_ref not in evidence_ids:
            violations.append(f"Finding {f_id} references non-existent evidence ID {ev_ref}.")

        if RFC1918_IPV4_REGEX.search(str(f.get("target"))):
            violations.append(f"Finding {f_id} target contains private IP: {f.get('target')}.")

    for i, r in enumerate(risks):
        r_id = str(r.get("id"))

        if str(r.get("assessment_id")) != run_id:
            violations.append(f"Risk snapshot {r_id} assessment_id does not match run_id {run_id}.")

        score = float(r.get("score", -1))
        if not (0.0 <= score <= 100.0):
            violations.append(f"Risk snapshot {r_id} score out of range: {score}.")

        if r.get("risk_level") not in VALID_RISK_LEVELS:
            violations.append(f"Risk snapshot {r_id} has invalid risk_level: {r.get('risk_level')}.")

        f_ref = str(r.get("finding_ref")) if r.get("finding_ref") else None
        if f_ref and f_ref not in finding_ids:
            violations.append(f"Risk snapshot {r_id} references non-existent finding ID {f_ref}.")

    # Deep recursive inspection for leaked private IPs, filesystem paths, or sensitive keys
    def _inspect_structure(obj: Any, path: str):
        if isinstance(obj, dict):
            for k, v in obj.items():
                current_path = f"{path}.{k}"
                if SENSITIVE_KEY_REGEX.search(k):
                    violations.append(f"Disallowed sensitive key detected at '{current_path}'.")
                _inspect_structure(v, current_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                _inspect_structure(item, f"{path}[{idx}]")
        elif isinstance(obj, str):
            if RFC1918_IPV4_REGEX.search(obj):
                violations.append(f"RFC1918 private IP detected at '{path}': {obj}")
            if WINDOWS_PATH_REGEX.search(obj):
                violations.append(f"Windows filesystem path detected at '{path}': {obj}")
            if LINUX_SYSTEM_PATH_REGEX.search(obj):
                violations.append(f"Linux filesystem path detected at '{path}': {obj}")

    _inspect_structure(run, "run")
    _inspect_structure(evidence, "evidence")
    _inspect_structure(findings, "findings")
    _inspect_structure(risks, "risks")

    return violations

