export function severityTone(
  severity: string | null | undefined,
): "default" | "ok" | "warn" | "danger" {
  const value = (severity || "").toUpperCase();
  if (value === "CRITICAL" || value === "HIGH") return "danger";
  if (value === "MEDIUM" || value === "MODERATE") return "warn";
  if (value === "LOW" || value === "INFO") return "ok";
  return "default";
}

export function severityBadgeClass(severity: string | null | undefined): string {
  const value = (severity || "").toUpperCase();
  if (value === "CRITICAL") {
    return "border-[var(--critical)]/40 bg-[var(--critical)]/15 text-[var(--critical)]";
  }
  if (value === "HIGH") {
    return "border-[var(--danger)]/40 bg-[var(--danger)]/15 text-[var(--danger)]";
  }
  if (value === "MEDIUM" || value === "MODERATE") {
    return "border-[var(--warn)]/40 bg-[var(--warn)]/15 text-[var(--warn)]";
  }
  if (value === "LOW") {
    return "border-[var(--ok)]/40 bg-[var(--ok)]/15 text-[var(--ok)]";
  }
  return "border-[var(--border)] bg-[var(--bg-elevated)] text-[var(--muted)]";
}

export function displayOrNotRecorded(value: string | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "Not recorded";
  }
  return value;
}

export function formatTelemetrySummary(
  telemetry:
    | {
        temperature: number;
        humidity: number;
        timestamp: string;
      }
    | null
    | undefined,
): { primary: string; lastRecorded: string | null } {
  if (!telemetry) {
    return { primary: "Not available", lastRecorded: null };
  }
  const recorded = new Date(telemetry.timestamp);
  const stamp = Number.isNaN(recorded.getTime())
    ? null
    : recorded.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
  return {
    primary: `${telemetry.temperature.toFixed(1)}°C · ${telemetry.humidity.toFixed(1)}%`,
    lastRecorded: stamp,
  };
}

export function formatGeneratedAt(value: string | null | undefined): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

export function formatConfidence(value: number): string {
  return `${(value * 100).toFixed(0)}%`;
}

export function formatFactorLabel(key: string): string {
  return key
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

const FINDING_TYPE_LABELS: Record<string, string> = {
  MQTT_WITHOUT_TLS: "MQTT communication without TLS",
  MQTT_ANONYMOUS_ACCESS: "MQTT anonymous access",
};

/** Human-readable label for a technical finding_type. Does not change API values. */
export function formatFindingTypeLabel(findingType: string): string {
  const known = FINDING_TYPE_LABELS[findingType];
  if (known) return known;
  return findingType
    .split("_")
    .filter(Boolean)
    .map((part, index) => {
      const lower = part.toLowerCase();
      if (index === 0) {
        return lower.charAt(0).toUpperCase() + lower.slice(1);
      }
      return lower;
    })
    .join(" ");
}

export function evidenceDisplay(
  evidence: Record<string, unknown>,
  key: string,
): string {
  const value = evidence[key];
  if (value === undefined || value === null || value === "") {
    return "Not recorded";
  }
  if (typeof value === "boolean") {
    return value ? "True" : "False";
  }
  if (Array.isArray(value)) {
    return value.length ? value.map(String).join(", ") : "Not recorded";
  }
  return String(value);
}
