/**
 * Centralized Asset Identification and Metadata Registry.
 *
 * Provides human-readable display names, asset categories, technical specs,
 * and secondary technical information for IoT lab assets.
 *
 * Rules:
 * - Every technical identifier (IP, hostname, asset_id) has a meaningful human-readable label.
 * - Never identify an asset using IP address alone.
 * - If an asset cannot be identified, return "Unknown asset" rather than guessing.
 * - Protect private laboratory network topology in public / read-only cloud mode.
 * - Derive authorization strictly from actual backend state, never static assumption.
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
  isAuthorized?: boolean;
  statusLabel?: string;
}

export const LAB_ASSETS: Record<string, AssetIdentity> = {
  AUTHORIZED_IOT: {
    id: "AUTHORIZED_IOT",
    displayName: "My IoT Environment",
    category: "ENVIRONMENT",
    categoryLabel: "Overall Environment",
    assetType: "Environment",
    description:
      "Security assessment of configured IoT devices and infrastructure components in the laboratory.",
    includes: "2 IoT devices and 1 MQTT broker",
    secondaryInfo: "3 lab assets · 2 IoT devices · 1 infrastructure component",
    purpose: "Overall security assessment",
    isAuthorized: false,
    statusLabel: "Lab Environment",
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
    isAuthorized: false,
    statusLabel: "Infrastructure",
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
    isAuthorized: false,
    statusLabel: "IoT Device",
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
    isAuthorized: false,
    statusLabel: "IoT Device",
  },
};

export interface GetLabAssetsOptions {
  isReadOnly?: boolean;
  devices?: Array<{
    device_id: string;
    is_authorized?: boolean;
    ip_address?: string | null;
    status?: string | null;
  }> | null;
}

/**
 * Returns the canonical laboratory asset definitions adapted to the active environment mode
 * and live backend device state.
 */
export function getLabAssets(options?: GetLabAssetsOptions): AssetIdentity[] {
  const isReadOnly = Boolean(options?.isReadOnly);
  const devices = options?.devices ?? [];

  const esp1Device = devices?.find(
    (d) => d.device_id.toUpperCase() === "ESP32-01" || d.device_id.toUpperCase() === "ESP32_01",
  );
  const esp2Device = devices?.find(
    (d) => d.device_id.toUpperCase() === "ESP32-02" || d.device_id.toUpperCase() === "ESP32_02",
  );

  const esp1Auth = Boolean(esp1Device?.is_authorized);
  const esp2Auth = Boolean(esp2Device?.is_authorized);
  const anyAuth = esp1Auth || esp2Auth;

  // 1. Overall Environment
  const envAsset: AssetIdentity = {
    ...LAB_ASSETS.AUTHORIZED_IOT,
    isAuthorized: isReadOnly ? false : anyAuth,
    statusLabel: isReadOnly
      ? "Monitored Assets"
      : anyAuth
        ? "Authorized Environment"
        : "Assessment Restricted",
    secondaryInfo: isReadOnly
      ? "Monitored lab assets · 2 IoT devices · 1 infrastructure component"
      : anyAuth
        ? "Authorized lab assets · 2 IoT devices · 1 infrastructure component"
        : "3 lab assets · 2 IoT devices · 1 infrastructure component",
  };

  // 2. MQTT Broker
  const brokerAsset: AssetIdentity = {
    ...LAB_ASSETS["MQTT-BROKER"],
    isAuthorized: isReadOnly ? false : anyAuth,
    ipAddress: isReadOnly ? undefined : LAB_ASSETS["MQTT-BROKER"].ipAddress,
    secondaryInfo: isReadOnly
      ? "Mosquitto 2.1.2 · Port 1883"
      : LAB_ASSETS["MQTT-BROKER"].secondaryInfo,
    statusLabel: isReadOnly
      ? "Telemetry Ingestion"
      : anyAuth
        ? "Authorized Infrastructure"
        : "Assessment Restricted",
  };

  // 3. ESP32-01
  const esp1Asset: AssetIdentity = {
    ...LAB_ASSETS["ESP32-01"],
    isAuthorized: isReadOnly ? false : esp1Auth,
    ipAddress: isReadOnly ? undefined : (esp1Device?.ip_address ?? LAB_ASSETS["ESP32-01"].ipAddress),
    secondaryInfo: isReadOnly
      ? "ESP32 Node · Temperature & Humidity Sensor"
      : esp1Device?.ip_address
        ? `${esp1Device.ip_address} · Temperature & Humidity Sensor`
        : LAB_ASSETS["ESP32-01"].secondaryInfo,
    statusLabel: isReadOnly
      ? (esp1Device?.status === "ONLINE" ? "Telemetry Active" : "Monitoring Only")
      : esp1Auth
        ? "Authorized for Assessment"
        : "Assessment Restricted",
  };

  // 4. ESP32-02
  const esp2Asset: AssetIdentity = {
    ...LAB_ASSETS["ESP32-02"],
    isAuthorized: isReadOnly ? false : esp2Auth,
    ipAddress: isReadOnly ? undefined : (esp2Device?.ip_address ?? LAB_ASSETS["ESP32-02"].ipAddress),
    secondaryInfo: isReadOnly
      ? "ESP32 Node · Temperature & Humidity Sensor"
      : esp2Device?.ip_address
        ? `${esp2Device.ip_address} · Temperature & Humidity Sensor`
        : LAB_ASSETS["ESP32-02"].secondaryInfo,
    statusLabel: isReadOnly
      ? (esp2Device?.status === "ONLINE" ? "Telemetry Active" : "Monitoring Only")
      : esp2Auth
        ? "Authorized for Assessment"
        : "Assessment Restricted",
  };

  return [envAsset, brokerAsset, esp1Asset, esp2Asset];
}

export interface ResolveAssetContext {
  port?: number | null;
  assetCategory?: string | null;
  assetType?: string | null;
  isReadOnly?: boolean;
  devices?: Array<{
    device_id: string;
    ip_address?: string | null;
    device_type?: string | null;
    is_authorized?: boolean;
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
  const isReadOnly = Boolean(context?.isReadOnly);

  // 1. Overall Environment
  if (upper === "AUTHORIZED_IOT" || upper === "ENVIRONMENT") {
    return {
      ...LAB_ASSETS.AUTHORIZED_IOT,
      secondaryInfo: isReadOnly
        ? "Monitored lab assets · 2 IoT devices · 1 infrastructure component"
        : LAB_ASSETS.AUTHORIZED_IOT.secondaryInfo,
    };
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
      ipAddress: isReadOnly ? undefined : ip,
      port,
      secondaryInfo: isReadOnly ? `Mosquitto 2.1.2 · Port ${port}` : `${ip} · Port ${port}`,
    };
  }

  // 3. ESP32-01
  if (
    trimmed === "10.32.252.105" ||
    upper === "ESP32-01" ||
    upper === "ESP32_01" ||
    upper === "ESP32-1"
  ) {
    const base = LAB_ASSETS["ESP32-01"];
    return {
      ...base,
      ipAddress: isReadOnly ? undefined : (base.ipAddress ?? trimmed),
      secondaryInfo: isReadOnly
        ? "ESP32 Node · Temperature & Humidity Sensor"
        : base.secondaryInfo,
    };
  }

  // 4. ESP32-02
  if (
    trimmed === "10.32.252.57" ||
    upper === "ESP32-02" ||
    upper === "ESP32_02" ||
    upper === "ESP32-2"
  ) {
    const base = LAB_ASSETS["ESP32-02"];
    return {
      ...base,
      ipAddress: isReadOnly ? undefined : (base.ipAddress ?? trimmed),
      secondaryInfo: isReadOnly
        ? "ESP32 Node · Temperature & Humidity Sensor"
        : base.secondaryInfo,
    };
  }

  // 5. Dynamic Device Inventory match
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
        ipAddress: isReadOnly ? undefined : (match.ip_address ?? trimmed),
        hardware: devType,
        sensor: "DHT22",
        purpose: "Telemetry and sensor collection",
        description: `Registered IoT device ${match.device_id} (${devType}).`,
        secondaryInfo: isReadOnly
          ? `${devType} Sensor · ${match.device_id}`
          : `${match.ip_address ?? trimmed} · ${devType} Sensor`,
        isAuthorized: isReadOnly ? false : Boolean(match.is_authorized),
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
    ipAddress: isReadOnly ? undefined : (trimmed.includes(".") ? trimmed : undefined),
    purpose: "Unregistered or external target",
    description: `Asset identifier: ${trimmed}`,
    secondaryInfo: isReadOnly ? "External Target" : `${trimmed}${portSuffix}`,
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
  context?: ResolveAssetContext,
): string {
  return resolveAssetIdentity(rawIdentifier, { ...context, port }).secondaryInfo;
}
