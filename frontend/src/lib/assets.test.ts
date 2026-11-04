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

// 3. Secondary technical information
check(getAssetSecondaryInfo("10.32.252.85", 1883).includes("10.32.252.85 · Port 1883"), "Broker secondary info");
check(getAssetSecondaryInfo("10.32.252.105").includes("10.32.252.105 · Temperature & Humidity Sensor"), "ESP32-01 secondary info");
check(getAssetSecondaryInfo("10.32.252.57").includes("10.32.252.57 · Temperature & Humidity Sensor"), "ESP32-02 secondary info");
check(getAssetSecondaryInfo("AUTHORIZED_IOT").includes("3 authorized assets"), "Environment secondary info");

// 4. Unknown asset fallback — never guess
const unknown = resolveAssetIdentity("192.168.1.99");
check(unknown.displayName === "Unknown asset", "Unregistered target resolves to Unknown asset");
check(unknown.secondaryInfo === "192.168.1.99", "Raw target preserved as secondary info");

// 5. Dynamic device inventory fallback
const dynamic = resolveAssetIdentity("10.99.99.1", {
  devices: [{ device_id: "ESP32-03", ip_address: "10.99.99.1", device_type: "ESP32" }],
});
check(dynamic.displayName === "ESP32-03 Sensor", "Dynamic device inventory recognized");

console.log("All asset identity tests passed!");
