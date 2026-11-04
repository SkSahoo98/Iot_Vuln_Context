const SENSITIVE_KEY =
  /pass(word|phrase)?|secret|token|credential|api[_-]?key|private[_-]?key|authorization/i;

export const REDACTED = "[redacted]";

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key);
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScalar(value: unknown): boolean {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

/** True when a JSON value cannot be shown meaningfully on a single line. */
export function isComplexValue(value: unknown): boolean {
  if (isPlainObject(value)) return true;
  return Array.isArray(value) && !value.every(isScalar);
}

export function formatJsonValue(value: unknown): string {
  if (value === null || value === undefined || value === "") {
    return "Not recorded";
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" || typeof value === "string") {
    return String(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return "None";
    if (value.every(isScalar)) return value.map(String).join(", ");
    return `${value.length} entries`;
  }
  if (isPlainObject(value)) return `${Object.keys(value).length} fields`;
  return String(value);
}

export function redactSensitive(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitive);
  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, inner]) => [
        key,
        isSensitiveKey(key) ? REDACTED : redactSensitive(inner),
      ]),
    );
  }
  return value;
}

export function formatNumber(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "Not recorded";
  }
  return value.toLocaleString(undefined, {
    maximumFractionDigits: 3,
    useGrouping: false,
  });
}

/** Backend remediation text, unchanged, or null when nothing was recorded. */
export function recordedRemediation(value: string | null | undefined): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function formatTargetPort(target: string, port: number | null): string {
  return port === null ? target : `${target}:${port}`;
}

const OBSERVED_SOURCES = new Set([
  "NMAP",
  "ACTIVE_PROBE",
  "HTTP_PROBE",
  "TLS_PROBE",
  "MQTT_PROBE",
]);

export type Provenance = {
  label: string;
  tone: "info" | "warn" | "neutral";
};

/** Classifies a backend provenance `source` without altering it. */
export function provenanceOf(source: unknown): Provenance | null {
  if (typeof source !== "string" || !source) return null;
  if (source === "CONFIGURATION") {
    return { label: "Configured input", tone: "warn" };
  }
  if (source === "NOT_ASSESSED_OR_NOT_OBSERVED") {
    return { label: "Not assessed or not observed", tone: "neutral" };
  }
  if (OBSERVED_SOURCES.has(source)) {
    return { label: "Observed evidence", tone: "info" };
  }
  return null;
}
