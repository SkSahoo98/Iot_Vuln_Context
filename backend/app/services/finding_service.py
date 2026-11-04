"""Legacy finding endpoint compatibility.

Authoritative findings are now created by assessment_service from persisted
active-probe evidence. Environment settings describe expected lab
configuration and must never be presented as detected vulnerabilities.
"""

from __future__ import annotations

from app.core.config import Settings
from app.schemas.api import FindingOut


def list_findings(settings: Settings) -> list[FindingOut]:
    """Return no legacy findings.

    Use POST /api/v1/assessments and GET /api/v1/assessments/{id} for
    evidence-linked findings. Keeping this endpoint as a valid empty response
    avoids breaking callers while removing the obsolete configuration-based
    detection path. ``settings`` is retained for API compatibility.
    """
    _ = settings
    return []
