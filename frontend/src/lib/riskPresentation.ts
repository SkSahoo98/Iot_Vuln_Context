import type { RiskItem } from "../api/types";
import { formatFindingTypeLabel } from "./format";

const FINDING_PLAIN_EXPLANATIONS: Record<string, string> = {
  MQTT_WITHOUT_TLS: "MQTT data is being transmitted without encryption.",
  MQTT_ANONYMOUS_ACCESS:
    "The MQTT broker accepts connections without authentication.",
};

/** One-sentence plain-language explanation for a finding type. */
export function formatFindingPlainExplanation(findingType: string): string {
  return (
    FINDING_PLAIN_EXPLANATIONS[findingType] ??
    `${formatFindingTypeLabel(findingType)} was reported from evidence-backed detection.`
  );
}

export type FactorPresentation = {
  label: string;
  state: string;
  detail: string;
  /** Higher internal values increase risk contribution for all IoT-RISK-v1 factors. */
  riskOriented: boolean;
};

const FACTOR_LABELS: Record<string, string> = {
  device_criticality: "Device Importance",
  network_exposure: "Network Exposure",
  authentication_security: "Authentication Protection",
  protocol_security: "Protocol Protection",
  firmware_security: "Firmware Risk Contribution",
};

function band(value: number): "low" | "mid" | "high" {
  if (value >= 0.7) return "high";
  if (value >= 0.4) return "mid";
  return "low";
}

/**
 * Plain-language presentation for risk factors.
 * Does not alter values — only describes what the engine's 0–1 risk contribution means.
 */
export function presentRiskFactor(
  key: string,
  value: number,
  evidence: Record<string, unknown>,
): FactorPresentation {
  const label =
    FACTOR_LABELS[key] ??
    key
      .split("_")
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");

  if (key === "authentication_security") {
    const anonymous = evidence.anonymous_allowed;
    if (value >= 0.5 || anonymous === true) {
      return {
        label,
        state: "Needs attention",
        detail: "No authentication configured",
        riskOriented: true,
      };
    }
    return {
      label,
      state: "Lower risk contribution",
      detail: "Anonymous access is not indicated",
      riskOriented: true,
    };
  }

  if (key === "protocol_security") {
    const tls = evidence.tls_enabled;
    if (value >= 0.5 || tls === false) {
      return {
        label,
        state: "Needs attention",
        detail: "TLS not enabled",
        riskOriented: true,
      };
    }
    return {
      label,
      state: "Lower risk contribution",
      detail: "TLS indicated as enabled",
      riskOriented: true,
    };
  }

  if (key === "device_criticality") {
    const level = band(value);
    return {
      label,
      state:
        level === "high"
          ? "High importance"
          : level === "mid"
            ? "Moderate importance"
            : "Lower importance",
      detail:
        level === "high"
          ? "This device role contributes more to contextual risk"
          : level === "mid"
            ? "This device role has moderate contextual influence"
            : "This device role contributes less to contextual risk",
      riskOriented: true,
    };
  }

  if (key === "network_exposure") {
    const level = band(value);
    return {
      label,
      state:
        level === "high"
          ? "Highly exposed"
          : level === "mid"
            ? "Moderately exposed"
            : "Limited exposure",
      detail:
        level === "high"
          ? "Broader network reachability increases contextual risk"
          : level === "mid"
            ? "Partial network reachability increases contextual risk"
            : "Limited reachability reduces contextual risk",
      riskOriented: true,
    };
  }

  if (key === "firmware_security") {
    const level = band(value);
    return {
      label,
      state:
        level === "high"
          ? "Higher firmware-related risk"
          : level === "mid"
            ? "Moderate firmware-related risk"
            : "Lower firmware-related risk",
      detail:
        "In this model, a higher value increases risk contribution (not a security grade).",
      riskOriented: true,
    };
  }

  const level = band(value);
  return {
    label,
    state:
      level === "high"
        ? "Higher risk contribution"
        : level === "mid"
          ? "Moderate risk contribution"
          : "Lower risk contribution",
    detail: "Contextual factor from the authoritative risk engine.",
    riskOriented: true,
  };
}

/**
 * Observed-fact lines derived only from evidence keys/values present in the API.
 * Does not invent observations that are not in the evidence object.
 */
export function formatEvidenceFacts(
  evidence: Record<string, unknown>,
): string[] {
  const facts: string[] = [];

  const service = evidence.service;
  if (typeof service === "string" && service.trim()) {
    const name = service.trim().toUpperCase();
    facts.push(
      name.includes("MQTT")
        ? "MQTT service detected"
        : `${service} service detected`,
    );
  }

  if (evidence.port !== undefined && evidence.port !== null && evidence.port !== "") {
    facts.push(`Port ${String(evidence.port)} detected`);
  }

  if (typeof evidence.host === "string" && evidence.host.trim()) {
    facts.push(`Broker host recorded: ${evidence.host.trim()}`);
  }

  const topics = evidence.observed_topics;
  if (Array.isArray(topics) && topics.length > 0) {
    facts.push("Observed MQTT topics recorded");
  }

  if (evidence.tls_enabled === false) {
    facts.push("TLS not enabled");
  } else if (evidence.tls_enabled === true) {
    facts.push("TLS enabled");
  }

  if (evidence.anonymous_allowed === true) {
    facts.push("Authentication not enabled");
  } else if (evidence.anonymous_allowed === false) {
    facts.push("Anonymous access not allowed");
  }

  if (typeof evidence.version === "string" && evidence.version.trim()) {
    facts.push(`Service version recorded: ${evidence.version.trim()}`);
  }

  // Fallback: any remaining keys as factual key/value statements (no invention)
  const covered = new Set([
    "service",
    "port",
    "host",
    "observed_topics",
    "tls_enabled",
    "anonymous_allowed",
    "version",
  ]);
  for (const [key, value] of Object.entries(evidence)) {
    if (covered.has(key)) continue;
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value) && value.length === 0) continue;
    const label = key.split("_").join(" ");
    facts.push(
      `${label}: ${Array.isArray(value) ? value.map(String).join(", ") : String(value)}`,
    );
  }

  return facts;
}

/** Context contribution points from authoritative score fields (not a new calculation of risk). */
export function contextContributionPoints(item: RiskItem): number {
  return Math.max(
    0,
    Number((item.score - item.base_severity_contribution).toFixed(2)),
  );
}
