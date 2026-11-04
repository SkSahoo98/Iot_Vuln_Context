"""
Hybrid AI-assisted explanation layer.

Primary: local Ollama (qwen3:8b) for evidence-grounded narrative.
Fallback: deterministic rule-based explanation if Ollama fails.

The LLM does NOT detect vulnerabilities or calculate risk scores.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import get_settings
from app.schemas.api import AIExplanationOut, FindingOut, RiskItemOut

logger = logging.getLogger("ai_explanation")

SYSTEM_PROMPT = """You are an evidence-grounded IoT cybersecurity explanation assistant.

Use ONLY the security evidence and calculated risk information provided by the application.

Do not invent:
- CVEs
- IP addresses
- ports
- devices
- protocols
- vulnerabilities
- services
- firmware versions
- attack results
- packet captures
- scan results
- authentication results
- security controls
- observations
- Internet exposure
- publish permissions
- subscribe permissions
- topic-level authorization outcomes
- device control capabilities

If information is not provided, explicitly state that it is unavailable or was not assessed.

Do not claim that an attack was actually performed.
Do not claim successful exploitation, successful manipulation, or device control.
Do not claim that anonymous clients can publish or subscribe unless the supplied evidence
explicitly establishes those permissions.
Do not claim that topic-level authorization is absent unless the supplied evidence
explicitly establishes that.

Describe attack scenarios only as potential scenarios supported by the supplied evidence.
For attack_scenario, explicitly state that it is a potential scenario and was not observed
during the assessment. Prefer cautious wording such as "could potentially", "may",
"depends on configuration", or "was not assessed" when capability is unknown.

Do not change or recalculate the application's risk score.
Do not change the finding severity.
Do not introduce new vulnerabilities that were not supplied.
Do not contradict supplied evidence.

Keep the explanation technically accurate and suitable for an M.Tech Cybersecurity project.
Use concise, clear language.

Return ONLY valid JSON with exactly these keys:
{
  "summary": "string",
  "why_it_matters": "string",
  "iot_context": "string",
  "risk_explanation": "string",
  "potential_impact": "string",
  "attack_scenario": "string",
  "remediation": ["string", "string"]
}

The risk_explanation MUST include the exact score number and risk_level text supplied by the application when available.
"""

REQUIRED_STRING_FIELDS = (
    "summary",
    "why_it_matters",
    "iot_context",
    "risk_explanation",
    "potential_impact",
    "attack_scenario",
)

CVE_PATTERN = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)

# Language that claims an attack already succeeded or overclaims capability.
BANNED_CLAIM_PHRASES = (
    "successfully intercepted",
    "successfully exploited",
    "successfully manipulated",
    "attacker successfully",
    "we intercepted",
    "attack was performed",
    "compromised the device",
    "controlled the device",
    "device control was demonstrated",
    "manipulated sensor data",
    "arbitrary clients can publish",
    "can publish to any topic",
    "can subscribe to any topic",
)


class ExplanationCache:
    """In-memory TTL cache shared by the AI explanation features."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[float, Any, str]] = {}

    def get(self, key: str) -> Any | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires_at, payload, _source = entry
        if time.monotonic() >= expires_at:
            self._entries.pop(key, None)
            return None
        return payload

    def store(self, key: str, payload: Any, source: str, ttl_sec: float) -> None:
        self._entries[key] = (time.monotonic() + ttl_sec, payload, source)

    def pop(self, key: str) -> None:
        self._entries.pop(key, None)

    def clear(self) -> None:
        self._entries.clear()


# Avoid Ollama stampedes when the dashboard polls the explanation endpoint.
CACHE_TTL_SUCCESS_SEC = 600.0
CACHE_TTL_FALLBACK_SEC = 45.0
_CACHE_TTL_SUCCESS_SEC = CACHE_TTL_SUCCESS_SEC
_CACHE_TTL_FALLBACK_SEC = CACHE_TTL_FALLBACK_SEC
_cache_lock = threading.Lock()
_explanation_cache = ExplanationCache()


def explain_finding(
    finding: FindingOut,
    risk: RiskItemOut | None = None,
    force_refresh: bool = False,
) -> AIExplanationOut:
    """
    Produce an AIExplanationOut using Ollama when available, otherwise
    the deterministic rule-based explanation.
    """
    fallback = _rule_based_explain_finding(finding, risk)
    cache_key = _cache_key(finding, risk)

    if force_refresh:
        with _cache_lock:
            _explanation_cache.pop(cache_key)
    else:
        cached = _get_cached(cache_key)
        if cached is not None:
            return cached

    with _cache_lock:
        if not force_refresh:
            cached = _get_cached(cache_key)
            if cached is not None:
                return cached

        try:
            settings = get_settings()
            logger.info(
                "Ollama request started (model=%s finding=%s)",
                settings.ollama_model,
                finding.finding_type,
            )
            llm_payload = _request_ollama_explanation(finding, risk)
            validated = _validate_llm_payload(llm_payload, finding, risk)
            if validated is None:
                logger.warning("Invalid AI response; fallback activated")
                _store_cache(cache_key, fallback, "fallback", _CACHE_TTL_FALLBACK_SEC)
                return fallback

            # Evidence lines always come from application evidence (never LLM).
            result = AIExplanationOut(
                finding_id=finding.finding_type,
                summary=validated["summary"],
                evidence=fallback.evidence,
                why_it_matters=validated["why_it_matters"],
                iot_context=validated["iot_context"],
                risk_explanation=validated["risk_explanation"],
                potential_impact=validated["potential_impact"],
                attack_scenario=_grounded_attack_scenario(
                    finding.finding_type,
                    validated["attack_scenario"],
                ),
                remediation=validated["remediation"],
                source="ollama",
                model=settings.ollama_model,
                generated_at=datetime.now(timezone.utc),
            )
            logger.info("AI explanation generated successfully via Ollama")
            _store_cache(cache_key, result, "ollama", _CACHE_TTL_SUCCESS_SEC)
            return result
        except httpx.TimeoutException:
            logger.warning("Ollama timeout; fallback activated")
            _store_cache(cache_key, fallback, "fallback", _CACHE_TTL_FALLBACK_SEC)
            return fallback
        except httpx.HTTPError as exc:
            logger.warning(
                "Ollama unavailable (%s); fallback activated",
                type(exc).__name__,
            )
            _store_cache(cache_key, fallback, "fallback", _CACHE_TTL_FALLBACK_SEC)
            return fallback
        except Exception as exc:  # noqa: BLE001 — must never break the API
            logger.warning(
                "Ollama unavailable/failed (%s); fallback activated",
                type(exc).__name__,
            )
            _store_cache(cache_key, fallback, "fallback", _CACHE_TTL_FALLBACK_SEC)
            return fallback


def _cache_key(finding: FindingOut, risk: RiskItemOut | None) -> str:
    score = risk.score if risk is not None else "none"
    level = risk.risk_level if risk is not None else "none"
    return f"{finding.finding_type}|{score}|{level}"


def _get_cached(cache_key: str) -> AIExplanationOut | None:
    return _explanation_cache.get(cache_key)


def _store_cache(
    cache_key: str,
    payload: AIExplanationOut,
    source: str,
    ttl_sec: float,
) -> None:
    _explanation_cache.store(cache_key, payload, source, ttl_sec)


def _rule_based_explain_finding(
    finding: FindingOut,
    risk: RiskItemOut | None = None,
) -> AIExplanationOut:
    """Deterministic evidence-grounded explanation (fallback and evidence source)."""
    evidence = finding.evidence or {}
    evidence_lines = [
        f"{key}: {value}"
        for key, value in evidence.items()
        if value is not None and value != "" and value != []
    ]

    host = evidence.get("host", "the MQTT broker")
    port = evidence.get("port", "unknown")
    tls = evidence.get("tls_enabled")
    anonymous = evidence.get("anonymous_allowed")

    risk_text = (
        f"Using {risk.score_version}, base severity {risk.base_severity} "
        f"contributes {risk.base_severity_contribution} points and IoT context "
        f"contributes the remainder, producing score {risk.score} "
        f"({risk.risk_level})."
        if risk
        else "Risk score was not calculated for this finding."
    )

    context_bits = []
    if tls is False:
        context_bits.append("MQTT traffic is not protected by TLS")
    if anonymous is True:
        context_bits.append("anonymous clients are permitted")
    iot_context = (
        "; ".join(context_bits) + "."
        if context_bits
        else "IoT contextual factors were supplied by the risk engine."
    )

    if finding.finding_type == "MQTT_WITHOUT_TLS":
        attack = _mqtt_without_tls_attack_scenario()
        remediation = [
            "Enable MQTT over TLS (typically port 8883).",
            "Configure ESP32 clients to validate the broker certificate.",
            "Re-scan and confirm tls_enabled evidence becomes true.",
        ]
    elif finding.finding_type == "MQTT_ANONYMOUS_ACCESS":
        attack = _mqtt_anonymous_access_attack_scenario()
        remediation = [
            "Disable anonymous access in Mosquitto.",
            "Require username/password or certificate authentication.",
            "Apply topic-level authorization for each ESP32 client.",
        ]
    else:
        attack = (
            "An attacker with lab-network access could abuse the observed "
            "misconfiguration according to the recorded evidence."
        )
        remediation = [finding.recommendation]

    return AIExplanationOut(
        finding_id=finding.finding_type,
        summary=finding.title,
        evidence=evidence_lines,
        why_it_matters=(
            "In IoT deployments, brokers often carry sensor and control data. "
            "Weak transport or authentication increases the chance that "
            "confidential telemetry or unauthorized commands are exposed."
        ),
        iot_context=iot_context,
        risk_explanation=risk_text,
        potential_impact=finding.impact,
        attack_scenario=attack,
        remediation=remediation,
        source="fallback",
        model=None,
        generated_at=datetime.now(timezone.utc),
    )


def _mqtt_without_tls_attack_scenario() -> str:
    """Evidence-grounded potential scenario for MQTT without TLS."""
    return (
        "A network attacker with access to the same communication path could "
        "potentially observe MQTT traffic because the connection is not "
        "protected by TLS. This is a potential attack scenario, not an attack "
        "observed during the assessment."
    )


def _mqtt_anonymous_access_attack_scenario() -> str:
    """Evidence-grounded potential scenario for anonymous MQTT access."""
    return (
        "An unauthorized client could potentially connect to the MQTT broker "
        "without authentication and attempt to access permitted MQTT topics. "
        "The actual ability to publish, subscribe, or control device functions "
        "depends on the broker's topic-level authorization configuration, which "
        "was not assessed in this finding. This is a potential attack scenario, "
        "not an attack observed during the assessment."
    )


def _grounded_attack_scenario(
    finding_type: str,
    llm_attack_scenario: str,
) -> str:
    """
    Keep known MQTT findings on evidence-bounded potential-scenario wording.
    Other findings keep the validated LLM text.
    """
    if finding_type == "MQTT_WITHOUT_TLS":
        return _mqtt_without_tls_attack_scenario()
    if finding_type == "MQTT_ANONYMOUS_ACCESS":
        return _mqtt_anonymous_access_attack_scenario()
    return llm_attack_scenario


def _build_user_prompt(finding: FindingOut, risk: RiskItemOut | None) -> str:
    payload: dict[str, Any] = {
        "finding": {
            "finding_type": finding.finding_type,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "description": finding.description,
            "impact": finding.impact,
            "recommendation": finding.recommendation,
            "evidence": finding.evidence,
        }
    }
    if risk is not None:
        payload["risk"] = {
            "finding_type": risk.finding_type,
            "base_severity": risk.base_severity,
            "score": risk.score,
            "risk_level": risk.risk_level,
            "score_version": risk.score_version,
            "calculation_method": risk.calculation_method,
            "base_severity_contribution": risk.base_severity_contribution,
            "context_score": risk.context_score,
            "factors": risk.factors,
            "factor_contributions": risk.factor_contributions,
        }

    return (
        "Using ONLY the following application-supplied security evidence and "
        "calculated risk data, produce the required JSON explanation.\n\n"
        f"{json.dumps(payload, indent=2, default=str)}"
    )


def _request_ollama_explanation(
    finding: FindingOut,
    risk: RiskItemOut | None,
) -> dict[str, Any]:
    return ollama_chat_json(
        SYSTEM_PROMPT,
        _build_user_prompt(finding, risk),
        temperature=0.2,
        num_predict=700,
    )


def ollama_chat_json(
    system_prompt: str,
    user_content: str,
    *,
    temperature: float,
    num_predict: int,
) -> dict[str, Any]:
    """
    One text-only chat call to the configured Ollama model, returning the
    parsed JSON object. No tools are offered to the model. Raises on HTTP
    errors, timeouts and malformed output.
    """
    settings = get_settings()
    url = f"{settings.ollama_base_url.rstrip('/')}/api/chat"
    body = {
        "model": settings.ollama_model,
        "stream": False,
        "format": "json",
        "think": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }

    with httpx.Client(timeout=settings.ollama_timeout) as client:
        response = client.post(url, json=body)
        response.raise_for_status()
        data = response.json()

    logger.info("Ollama response received")
    content = data.get("message", {}).get("content", "")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Empty Ollama message content")

    cleaned = _strip_think_blocks(content).strip()
    # Some models wrap JSON in markdown fences despite format=json.
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("Ollama JSON root must be an object")
    return parsed


def _strip_think_blocks(text: str) -> str:
    """Remove Qwen-style <think>...</think> blocks if present."""
    return re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()


def _validate_llm_payload(
    payload: dict[str, Any],
    finding: FindingOut,
    risk: RiskItemOut | None,
) -> dict[str, Any] | None:
    for field in REQUIRED_STRING_FIELDS:
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            logger.warning("AI response missing/invalid field: %s", field)
            return None

    remediation = payload.get("remediation")
    if isinstance(remediation, str) and remediation.strip():
        remediation = [remediation.strip()]
    if not isinstance(remediation, list) or not remediation:
        logger.warning("AI response remediation must be a non-empty list")
        return None
    if not all(isinstance(item, str) and item.strip() for item in remediation):
        logger.warning("AI response remediation items must be non-empty strings")
        return None

    # Soft contradiction checks against authoritative application data.
    joined = " ".join(
        [
            payload["summary"],
            payload["why_it_matters"],
            payload["iot_context"],
            payload["risk_explanation"],
            payload["potential_impact"],
            payload["attack_scenario"],
            " ".join(remediation),
        ]
    ).lower()

    # Reject invented CVE identifiers.
    if CVE_PATTERN.search(joined):
        logger.warning("AI response invented a CVE identifier; rejecting")
        return None

    if any(phrase in joined for phrase in BANNED_CLAIM_PHRASES):
        logger.warning("AI response claimed completed attack or overclaimed capability; rejecting")
        return None

    risk_explanation = payload["risk_explanation"]
    if risk is not None:
        score_text = str(risk.score)
        level_text = str(risk.risk_level).upper()
        if score_text not in risk_explanation or level_text not in risk_explanation.upper():
            logger.warning(
                "AI risk_explanation missing authoritative score/level; rejecting"
            )
            return None

    return {
        "summary": payload["summary"].strip(),
        "why_it_matters": payload["why_it_matters"].strip(),
        "iot_context": payload["iot_context"].strip(),
        "risk_explanation": risk_explanation.strip(),
        "potential_impact": payload["potential_impact"].strip(),
        "attack_scenario": payload["attack_scenario"].strip(),
        "remediation": [item.strip() for item in remediation],
    }
