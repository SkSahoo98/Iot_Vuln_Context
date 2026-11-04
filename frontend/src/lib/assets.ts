/**
 * Centralized Asset Identification and Metadata Registry.
 *
 * Provides human-readable display names, asset categories, technical specs,
 * and secondary technical information for all authorized IoT lab assets.
 *
 * Rules:
 * - Every technical identifier (IP, hostname, asset_id) has a meaningful human-readable label.
 * - Never identify an asset using IP address alone.
 * - If an asset cannot be identified, return "Unknown asset" rather than guessing.
 */

export type AssetCategory = "ENVIRONMENT" | "IOT_INFRASTRUCTURE" | "IOT_DEVICE" | "UNKNOWN";

export interface AssetIdentity {
  id: string;
  displayName: string;
  category: AssetCategory;
  categoryLabel: string;
  assetType: string;
  ipAddress?: string;
  port?: number;
  software?: string;
  hardware?: string;
  sensor?: string;
  purpose: string;
  description: string;
  secondaryInfo: string;
  includes?: string;
}

export const LAB_ASSETS: Record<string, AssetIdentity> = {
  AUTHORIZED_IOT: {
    id: "AUTHORIZED_IOT",
    displayName: "My IoT Environment",
    category: "ENVIRONMENT",
    categoryLabel: "Overall Environment",
    assetType: "Environment",
    description:
      "Overall security assessment of all authorized IoT devices and infrastructure components in the laboratory.",
    includes: "2 IoT devices and 1 MQTT broker",
    secondaryInfo: "3 authorized assets · 2 IoT devices · 1 infrastructure component",
    purpose: "Overall security assessment",
  },
  "MQTT-BROKER": {
    id: "MQTT-BROKER",
    displayName: "MQTT Broker (Windows Laptop)",
    category: "IOT_INFRASTRUCTURE",
    categoryLabel: "Infrastructure",
    assetType: "MQTT_BROKER",
    ipAddress: "10.32.252.85",
    port: 1883,
    software: "Mosquitto 2.1.2",
    purpose: "Central MQTT communication server",
    description:
      "The central communication server running Mosquitto. Both ESP32 devices send their sensor readings to this broker using MQTT.",
    secondaryInfo: "10.32.252.85 · Port 1883",
  },
  "ESP32-01": {
    id: "ESP32-01",
    displayName: "ESP32 Sensor 01",
    category: "IOT_DEVICE",
    categoryLabel: "IoT Device",
    assetType: "ESP32",
    ipAddress: "10.32.252.105",
    hardware: "ESP32",
    sensor: "DHT22",
    purpose: "Temperature and humidity collection",
    description:
      "The first ESP32 development board connected to a DHT22 temperature and humidity sensor. It publishes sensor readings to the MQTT broker.",
    secondaryInfo: "10.32.252.105 · Temperature & Humidity Sensor",
  },
  "ESP32-02": {
    id: "ESP32-02",
    displayName: "ESP32 Sensor 02",
    category: "IOT_DEVICE",
    categoryLabel: "IoT Device",
    assetType: "ESP32",
    ipAddress: "10.32.252.57",
    hardware: "ESP32",
    sensor: "DHT22",
    purpose: "Temperature and humidity collection",
    description:
      "The second ESP32 development board connected to a DHT22 temperature and humidity sensor. It publishes sensor readings to the MQTT broker.",
    secondaryInfo: "10.32.252.57 · Temperature & Humidity Sensor",
  },
};

/**
 * Returns the four canonical laboratory asset definitions for display in the Lab Assets section.
 */
export function getLabAssets(): AssetIdentity[] {
  return [
    LAB_ASSETS.AUTHORIZED_IOT,
    LAB_ASSETS["MQTT-BROKER"],
    LAB_ASSETS["ESP32-01"],
    LAB_ASSETS["ESP32-02"],
  ];
}

export interface ResolveAssetContext {
  port?: number | null;
  assetCategory?: string | null;
  assetType?: string | null;
  devices?: Array<{
    device_id: string;
    ip_address?: string | null;
    device_type?: string | null;
  }>;
}

/**
 * Centralized resolver to turn any raw technical target/IP/asset_id into a human-readable AssetIdentity.
 */
export function resolveAssetIdentity(
  rawIdentifier: string | null | undefined,
  context?: ResolveAssetContext,
): AssetIdentity {
  if (!rawIdentifier || typeof rawIdentifier !== "string") {
    return {
      id: "UNKNOWN",
      displayName: "Unknown asset",
      category: "UNKNOWN",
      categoryLabel: "Asset",
      assetType: "Unknown",
      purpose: "Unidentified target",
      description: "No asset identifier provided.",
      secondaryInfo: "Not identified",
    };
  }

  const trimmed = rawIdentifier.trim();
  const upper = trimmed.toUpperCase();

  // 1. Overall Environment
  if (upper === "AUTHORIZED_IOT" || upper === "ENVIRONMENT") {
    return LAB_ASSETS.AUTHORIZED_IOT;
  }

  // 2. MQTT Broker
  if (
    trimmed === "10.32.252.85" ||
    upper === "MQTT-BROKER" ||
    upper === "MQTT_BROKER" ||
    upper === "BROKER" ||
    trimmed === "MT67.local" ||
    (context?.assetType?.toUpperCase() === "MQTT_BROKER")
  ) {
    const base = LAB_ASSETS["MQTT-BROKER"];
    const port = context?.port ?? base.port ?? 1883;
    const ip = trimmed.includes(".") ? trimmed : base.ipAddress;
    return {
      ...base,
      ipAddress: ip,
      port,
      secondaryInfo: `${ip} · Port ${port}`,
    };
  }

  // 3. ESP32-01
  if (
    trimmed === "10.32.252.105" ||
    upper === "ESP32-01" ||
    upper === "ESP32_01" ||
    upper === "ESP32-1"
  ) {
    return LAB_ASSETS["ESP32-01"];
  }

  // 4. ESP32-02
  if (
    trimmed === "10.32.252.57" ||
    upper === "ESP32-02" ||
    upper === "ESP32_02" ||
    upper === "ESP32-2"
  ) {
    return LAB_ASSETS["ESP32-02"];
  }

  // 5. Dynamic Device Inventory match (e.g. if lab IPs change dynamically)
  if (context?.devices?.length) {
    const match = context.devices.find(
      (d) =>
        d.device_id.toUpperCase() === upper ||
        (d.ip_address && d.ip_address.trim() === trimmed),
    );
    if (match) {
      const devType = match.device_type ?? "ESP32";
      return {
        id: match.device_id,
        displayName: `${match.device_id} Sensor`,
        category: "IOT_DEVICE",
        categoryLabel: "IoT Device",
        assetType: devType,
        ipAddress: match.ip_address ?? trimmed,
        hardware: devType,
        sensor: "DHT22",
        purpose: "Telemetry and sensor collection",
        description: `Registered IoT device ${match.device_id} (${devType}).`,
        secondaryInfo: `${match.ip_address ?? trimmed} · ${devType} Sensor`,
      };
    }
  }

  // 6. Unknown / Unidentified — Never guess
  const portSuffix = context?.port ? ` · Port ${context.port}` : "";
  return {
    id: trimmed,
    displayName: "Unknown asset",
    category: "UNKNOWN",
    categoryLabel: "Asset",
    assetType: "Unknown",
    ipAddress: trimmed.includes(".") ? trimmed : undefined,
    purpose: "Unregistered or external target",
    description: `Asset identifier: ${trimmed}`,
    secondaryInfo: `${trimmed}${portSuffix}`,
  };
}

/**
 * Returns the human-readable display name for any technical target/IP/asset_id.
 */
export function getAssetDisplayName(
  rawIdentifier: string | null | undefined,
  context?: ResolveAssetContext,
): string {
  return resolveAssetIdentity(rawIdentifier, context).displayName;
}

/**
 * Returns secondary technical information (e.g. "10.32.252.85 · Port 1883").
 */
export function getAssetSecondaryInfo(
  rawIdentifier: string | null | undefined,
  port?: number | null,
): string {
  return resolveAssetIdentity(rawIdentifier, { port }).secondaryInfo;
}

