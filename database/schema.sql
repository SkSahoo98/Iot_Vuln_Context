-- =============================================================================
-- IoT Security Framework — Initial PostgreSQL Schema
-- Database: iot_security (must already exist)
-- =============================================================================
-- Purpose:
--   Minimal, production-ready foundation for:
--     - ESP32 device inventory
--     - DHT22 MQTT sensor telemetry
--   Designed so later modules (Nmap scanning, findings, CVEs, IDRS risk scoring,
--   AI/ML) can attach via foreign keys to devices.id without rewriting this core.
--
-- Safety:
--   - Does NOT create or drop a database
--   - Does NOT drop tables
--   - Uses CREATE TABLE IF NOT EXISTS only
--
-- Apply (example):
--   psql -U postgres -d iot_security -f database/schema.sql
-- =============================================================================

-- Prefer UTC-aware timestamps for auditability across lab machines.
SET timezone = 'UTC';

-- -----------------------------------------------------------------------------
-- devices
-- Inventory of authorized IoT assets (ESP32-01, ESP32-02, gateways, etc.).
-- One row per physical/logical device. MQTT collector resolves device_id
-- (e.g. "ESP32-01") to this table before inserting sensor_data.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    -- Surrogate primary key used by all future FKs (scans, findings, risk).
    id                  BIGSERIAL PRIMARY KEY,

    -- Stable lab identity matching MQTT payload field "device_id"
    -- Examples: ESP32-01, ESP32-02
    device_id           VARCHAR(64)  NOT NULL,

    -- Last-known network addressing (updated by discovery/scans later)
    ip_address          INET,
    mac_address         MACADDR,

    -- Coarse classification for inventory and risk context
    -- Examples: ESP32, SENSOR, GATEWAY, RASPBERRY_PI
    device_type         VARCHAR(50)  NOT NULL DEFAULT 'ESP32',

    -- Reported or flashed firmware string (important for risk / CVE mapping later)
    firmware_version    VARCHAR(64),

    -- Operational presence in the lab (not a security severity)
    -- ONLINE / OFFLINE / UNKNOWN
    status              VARCHAR(20)  NOT NULL DEFAULT 'UNKNOWN',

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_devices_device_id UNIQUE (device_id),
    CONSTRAINT ck_devices_status
        CHECK (status IN ('ONLINE', 'OFFLINE', 'UNKNOWN'))
);

COMMENT ON TABLE devices IS
    'Authorized IoT device inventory. Natural key is device_id (e.g. ESP32-01).';

COMMENT ON COLUMN devices.id IS
    'Surrogate PK. Future scan/finding/risk tables should FK to this column.';

COMMENT ON COLUMN devices.device_id IS
    'Business identifier from firmware/MQTT JSON (device_id). Must be unique.';

COMMENT ON COLUMN devices.ip_address IS
    'Last known IPv4/IPv6 address. Nullable until discovery or manual registration.';

COMMENT ON COLUMN devices.mac_address IS
    'Last known MAC address. Nullable until discovery or manual registration.';

COMMENT ON COLUMN devices.device_type IS
    'Device class for inventory filtering and future criticality rules.';

COMMENT ON COLUMN devices.firmware_version IS
    'Firmware string used later for age/CVE correlation in the risk engine.';

COMMENT ON COLUMN devices.status IS
    'Connectivity/operational status derived from MQTT heartbeats or scans.';

COMMENT ON COLUMN devices.created_at IS
    'When the device was first registered in the database.';

COMMENT ON COLUMN devices.updated_at IS
    'Last metadata change (IP, status, firmware). Application should refresh this.';

CREATE INDEX IF NOT EXISTS idx_devices_ip_address
    ON devices (ip_address);

CREATE INDEX IF NOT EXISTS idx_devices_mac_address
    ON devices (mac_address);

CREATE INDEX IF NOT EXISTS idx_devices_device_type
    ON devices (device_type);

CREATE INDEX IF NOT EXISTS idx_devices_status
    ON devices (status);

-- -----------------------------------------------------------------------------
-- sensor_data
-- Time-series DHT22 readings received over MQTT.
-- Topics:
--   ESP32-01 → iot/esp32/01/sensor
--   ESP32-02 → iot/esp32/02/sensor
-- Payload example:
--   {"device_id":"ESP32-01","temperature":30.40,"humidity":76.90}
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sensor_data (
    id              BIGSERIAL PRIMARY KEY,

    -- FK to devices.device_id so MQTT inserts can use the string identity
    -- from the JSON payload without an extra id lookup in the hot path.
    -- ON DELETE RESTRICT: never lose telemetry by deleting a device row casually.
    device_id       VARCHAR(64)     NOT NULL
        REFERENCES devices (device_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    -- DHT22 Celsius reading
    temperature     NUMERIC(5, 2)   NOT NULL,

    -- DHT22 relative humidity percentage
    humidity        NUMERIC(5, 2)   NOT NULL,

    -- When the reading was observed (collector clock or device clock if trusted)
    "timestamp"     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_sensor_data_humidity
        CHECK (humidity >= 0 AND humidity <= 100)
);

COMMENT ON TABLE sensor_data IS
    'Append-only MQTT DHT22 telemetry. Do not update historical rows; insert new ones.';

COMMENT ON COLUMN sensor_data.device_id IS
    'Matches MQTT JSON device_id and devices.device_id (e.g. ESP32-01).';

COMMENT ON COLUMN sensor_data.temperature IS
    'Temperature in Celsius from DHT22.';

COMMENT ON COLUMN sensor_data.humidity IS
    'Relative humidity percentage from DHT22 (0–100).';

COMMENT ON COLUMN sensor_data."timestamp" IS
    'Observation time. Used for dashboards, anomaly windows, and audit trails.';

-- Fast “latest readings for a device” and time-range queries
CREATE INDEX IF NOT EXISTS idx_sensor_data_device_id_timestamp
    ON sensor_data (device_id, "timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_sensor_data_timestamp
    ON sensor_data ("timestamp" DESC);

-- -----------------------------------------------------------------------------
-- Seed authorized lab devices (safe upsert — no deletes)
-- -----------------------------------------------------------------------------
INSERT INTO devices (device_id, device_type, firmware_version, status)
VALUES
    ('ESP32-01', 'ESP32', '1.0.0', 'UNKNOWN'),
    ('ESP32-02', 'ESP32', '1.0.0', 'UNKNOWN')
ON CONFLICT (device_id) DO NOTHING;

-- =============================================================================
-- Future extension points (NOT created here — avoid over-engineering)
-- =============================================================================
-- Later phases can add tables that reference devices.id, for example:
--   scan_sessions(device_pk → devices.id)
--   findings(device_pk → devices.id)
--   risk_scores(device_pk → devices.id)
--   ml_predictions(device_pk → devices.id)
-- Sensor health (missing heartbeats, out-of-range humidity) can become
-- configuration findings that feed the Dynamic IoT Risk Score (IDRS).
-- =============================================================================
