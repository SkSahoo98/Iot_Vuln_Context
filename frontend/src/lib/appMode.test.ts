import { resolveAppMode } from "./appMode.ts";
import type { BackendHealth } from "../api/types.ts";

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

// 1. Production cloud backend
const prodHealth: BackendHealth = {
  status: "ok",
  service: "iot-security-framework",
  environment: "production",
  read_only_mode: true,
  active_assessment_supported: false,
};
const prodMode = resolveAppMode(prodHealth);
check(prodMode.isReadOnly === true, "Production is read-only");
check(prodMode.isCloudProduction === true, "Production is marked as cloud production");
check(prodMode.activeAssessmentSupported === false, "Production has active assessments disabled");
check(prodMode.modeLabel === "Cloud Read-Only", "Production modeLabel is 'Cloud Read-Only'");

// 2. Local lab with allowlist configured
const labHealth: BackendHealth = {
  status: "ok",
  service: "iot-security-framework",
  environment: "development",
  read_only_mode: false,
  active_assessment_supported: true,
};
const labMode = resolveAppMode(labHealth);
check(labMode.isReadOnly === false, "Local lab is not read-only");
check(labMode.isCloudProduction === false, "Local lab is not cloud production");
check(labMode.activeAssessmentSupported === true, "Local lab supports active assessment");
check(labMode.modeLabel === "Active Laboratory", "Local lab modeLabel is 'Active Laboratory'");

// 3. Local lab with empty allowlist
const labRestrictedHealth: BackendHealth = {
  status: "ok",
  service: "iot-security-framework",
  environment: "development",
  read_only_mode: false,
  active_assessment_supported: false,
};
const restrictedMode = resolveAppMode(labRestrictedHealth);
check(restrictedMode.isReadOnly === false, "Restricted lab is not globally read-only");
check(restrictedMode.activeAssessmentSupported === false, "Restricted lab does not support assessments");
check(restrictedMode.modeLabel === "Local Lab (Assessment Restricted)", "Restricted mode label");

// 4. Backend unavailable / null (fail-closed)
const closedMode = resolveAppMode(null);
check(closedMode.isReadOnly === true, "Null health fails closed as read-only");
check(closedMode.activeAssessmentSupported === false, "Null health fails closed with assessment disabled");

console.log("All appMode unit tests passed!");
