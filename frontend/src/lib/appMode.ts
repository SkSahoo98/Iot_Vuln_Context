import type { BackendHealth } from "../api/types";

export interface AppModeInfo {
  isReadOnly: boolean;
  isCloudProduction: boolean;
  modeLabel: string;
  activeAssessmentSupported: boolean;
}

/**
 * Centrally determines the application operating mode.
 *
 * The backend health capability response is the primary authority.
 *
 * Requirements:
 * 1. If backend health capability is unavailable / failing, fail closed:
 *    activeAssessmentSupported is false, isReadOnly is true.
 * 2. In Cloud Production (environment === 'production' or read_only_mode === true),
 *    active assessment is prohibited and read-only monitoring is enforced.
 * 3. In Local Lab Mode, active assessment is enabled only when the backend explicitly
 *    permits it (active_assessment_supported === true).
 * 4. A local Vite production build still supports local lab assessments if the local
 *    backend permits them.
 */
export function resolveAppMode(health?: BackendHealth | null): AppModeInfo {
  if (!health) {
    const isCloudProd = Boolean(
      typeof import.meta !== "undefined" && import.meta.env?.PROD,
    );
    return {
      isReadOnly: true,
      isCloudProduction: isCloudProd,
      modeLabel: isCloudProd ? "Cloud Read-Only" : "Connecting...",
      activeAssessmentSupported: false,
    };
  }

  const env = (health.environment || "").toLowerCase();
  const isCloudProduction = env === "production";
  const isReadOnly = Boolean(health.read_only_mode || isCloudProduction);
  const activeAssessmentSupported = Boolean(health.active_assessment_supported);

  let modeLabel = "Active Laboratory";
  if (isCloudProduction || isReadOnly) {
    modeLabel = "Cloud Read-Only";
  } else if (!activeAssessmentSupported) {
    modeLabel = "Local Lab (Assessment Restricted)";
  }

  return {
    isReadOnly,
    isCloudProduction,
    modeLabel,
    activeAssessmentSupported,
  };
}
