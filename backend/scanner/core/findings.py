"""Build catalog-backed findings from evidence."""

from __future__ import annotations

from scanner.core.catalog import get_check
from scanner.core.models import Evidence, FindingCandidate


def make_finding(
    check_id: str,
    evidence: Evidence,
    *,
    description: str,
    confidence: float,
) -> FindingCandidate:
    check = get_check(check_id)
    return FindingCandidate(
        finding_id=check.check_id,
        finding_type=check.finding_type,
        category=check.category,
        title=check.title,
        severity=check.severity,
        confidence=confidence,
        description=description,
        remediation=check.remediation,
        target=evidence.target,
        port=evidence.port,
        evidence=evidence,
    )
