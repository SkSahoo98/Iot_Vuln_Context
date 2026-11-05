import {
  getAssetDisplayName,
  getAssetSecondaryInfo,
  getLabAssets,
  resolveAssetIdentity,
} from "./assets.ts";

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

// 1. Canonical assets
const assets = getLabAssets();
check(assets.length === 4, "4 canonical lab assets returned");
check(assets[0].displayName === "My IoT Environment", "Asset 1 is My IoT Environment");
check(assets[1].displayName === "MQTT Broker (Windows Laptop)", "Asset 2 is MQTT Broker (Windows Laptop)");
check(assets[2].displayName === "ESP32 Sensor 01", "Asset 3 is ESP32 Sensor 01");
check(assets[3].displayName === "ESP32 Sensor 02", "Asset 4 is ESP32 Sensor 02");

// 2. Technical identifiers to display labels
check(getAssetDisplayName("AUTHORIZED_IOT") === "My IoT Environment", "AUTHORIZED_IOT -> My IoT Environment");
check(getAssetDisplayName("10.32.252.85") === "MQTT Broker (Windows Laptop)", "10.32.252.85 -> MQTT Broker (Windows Laptop)");
check(getAssetDisplayName("MQTT-BROKER") === "MQTT Broker (Windows Laptop)", "MQTT-BROKER -> MQTT Broker (Windows Laptop)");
check(getAssetDisplayName("10.32.252.105") === "ESP32 Sensor 01", "10.32.252.105 -> ESP32 Sensor 01");
check(getAssetDisplayName("ESP32-01") === "ESP32 Sensor 01", "ESP32-01 -> ESP32 Sensor 01");
check(getAssetDisplayName("10.32.252.57") === "ESP32 Sensor 02", "10.32.252.57 -> ESP32 Sensor 02");
check(getAssetDisplayName("ESP32-02") === "ESP32 Sensor 02", "ESP32-02 -> ESP32 Sensor 02");

// 3. Secondary technical information (Local Lab mode default)
check(getAssetSecondaryInfo("10.32.252.85", 1883).includes("10.32.252.85 · Port 1883"), "Broker secondary info");
check(getAssetSecondaryInfo("10.32.252.105").includes("10.32.252.105 · Temperature & Humidity Sensor"), "ESP32-01 secondary info");
check(getAssetSecondaryInfo("10.32.252.57").includes("10.32.252.57 · Temperature & Humidity Sensor"), "ESP32-02 secondary info");
check(getAssetSecondaryInfo("AUTHORIZED_IOT").includes("lab assets"), "Environment secondary info");

// 4. Unknown asset fallback — never guess
const unknown = resolveAssetIdentity("192.168.1.99");
check(unknown.displayName === "Unknown asset", "Unregistered target resolves to Unknown asset");
check(unknown.secondaryInfo === "192.168.1.99", "Raw target preserved as secondary info");

// 5. Dynamic device inventory fallback
const dynamic = resolveAssetIdentity("10.99.99.1", {
  devices: [{ device_id: "ESP32-03", ip_address: "10.99.99.1", device_type: "ESP32" }],
});
check(dynamic.displayName === "ESP32-03 Sensor", "Dynamic device inventory recognized");

// 6. Public Cloud / Read-Only Mode IP Protection & Non-Authorization
const cloudAssets = getLabAssets({ isReadOnly: true });
check(cloudAssets.length === 4, "4 cloud assets returned");
check(cloudAssets[0].isAuthorized === false, "Cloud environment is not authorized for scans");
check(cloudAssets[1].ipAddress === undefined, "Cloud broker hides private IP");
check(!cloudAssets[1].secondaryInfo.includes("10.32.252.85"), "Cloud broker secondary info does not leak private IP");
check(cloudAssets[2].ipAddress === undefined, "Cloud ESP32-01 hides private IP");
check(!cloudAssets[2].secondaryInfo.includes("10.32.252.105"), "Cloud ESP32-01 does not leak private IP");
check(cloudAssets[2].isAuthorized === false, "Cloud ESP32-01 is not authorized");
check(cloudAssets[2].statusLabel === "Monitoring Only", "Cloud ESP32-01 labeled Monitoring Only");

// 7. Local Lab Mode with dynamic backend authorization
const localAssets = getLabAssets({
  isReadOnly: false,
  devices: [
    { device_id: "ESP32-01", is_authorized: true, ip_address: "10.32.252.105", status: "ONLINE" },
    { device_id: "ESP32-02", is_authorized: false, ip_address: "10.32.252.57", status: "ONLINE" },
  ],
});
check(localAssets[0].isAuthorized === true, "Local env is authorized when any device is authorized");
check(localAssets[2].isAuthorized === true, "Local ESP32-01 is authorized based on API");
check(localAssets[2].statusLabel === "Authorized for Assessment", "Local ESP32-01 labeled Authorized for Assessment");
check(localAssets[3].isAuthorized === false, "Local ESP32-02 is unauthorized when API says so");
check(localAssets[3].statusLabel === "Assessment Restricted", "Local ESP32-02 labeled Assessment Restricted");
check(localAssets[2].ipAddress === "10.32.252.105", "Local ESP32-01 preserves IP for local scanning");

console.log("All asset identity tests passed!");
