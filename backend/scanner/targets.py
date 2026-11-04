"""Strict allowlist validation for authorized assessment targets."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address


class TargetNotAllowedError(ValueError):
    """Raised when a target is invalid or outside the explicit allowlist."""


def parse_allowed_targets(value: str) -> frozenset[IPv4Address | IPv6Address]:
    """Parse comma-separated private/loopback IP literals.

    Hostnames and CIDR ranges are intentionally unsupported: one assessment
    request always addresses one explicitly listed laboratory IP.
    """
    allowed: set[IPv4Address | IPv6Address] = set()
    for raw in value.split(","):
        candidate = raw.strip()
        if not candidate:
            continue
        if "/" in candidate:
            raise ValueError("CIDR ranges are not permitted in the target allowlist")
        try:
            address = ip_address(candidate)
        except ValueError as exc:
            raise ValueError(
                f"Allowlist entry must be an IP literal: {candidate!r}"
            ) from exc
        if not (address.is_private or address.is_loopback):
            raise ValueError(
                f"Allowlist entry must be private or loopback: {address}"
            )
        allowed.add(address)
    return frozenset(allowed)


def validate_target(
    target: str,
    allowed_targets: str,
) -> IPv4Address | IPv6Address:
    """Return the canonical IP if it is explicitly allowlisted."""
    candidate = target.strip()
    if not candidate or "/" in candidate:
        raise TargetNotAllowedError(
            "Target must be one explicitly allowlisted IP address; CIDR is not allowed"
        )
    try:
        address = ip_address(candidate)
    except ValueError as exc:
        raise TargetNotAllowedError(
            "Target must be an IP literal; hostnames and scan ranges are not allowed"
        ) from exc

    allowed = parse_allowed_targets(allowed_targets)
    if address not in allowed:
        raise TargetNotAllowedError(
            f"Target {address} is not in ASSESSMENT_ALLOWED_TARGETS"
        )
    return address
