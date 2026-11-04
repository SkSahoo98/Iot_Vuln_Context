# ESP32 Firmware & Authenticated MQTT Telemetry (Lab Devices)

These sketches publish DHT22 telemetry and the device's current Wi-Fi IP (`WiFi.localIP()`) to the Mosquitto MQTT broker using authenticated credentials.

| Device | Folder | Topic | `device_id` | MQTT Account |
| --- | --- | --- | --- | --- |
| ESP32-01 | `esp32_device_01/` | `iot/esp32/01/sensor` | `ESP32-01` | `esp32_01` |
| ESP32-02 | `esp32_device_02/` | `iot/esp32/02/sensor` | `ESP32-02` | `esp32_02` |

---

## 1. Libraries Required

Install the following libraries in Arduino IDE / PlatformIO:

- **WiFi** (built into the ESP32 Arduino Core)
- **PubSubClient** (by Nick O'Leary)
- **DHT sensor library** (by Adafruit)
- **Adafruit Unified Sensor** (Adafruit dependency)

---

## 2. Secrets Configuration (`secrets.h`)

Each device folder has its own `secrets.h.example`. Create a local `secrets.h` file in each device directory:

### For ESP32-01 (`firmware/esp32_device_01/secrets.h`)

```cpp
#pragma once

static const char *WIFI_SSID = "YOUR_LAB_WIFI_SSID";
static const char *WIFI_PASSWORD = "YOUR_LAB_WIFI_PASSWORD";

// Mosquitto broker host
static const char *MQTT_BROKER_HOST = "10.32.252.85";
static const uint16_t MQTT_BROKER_PORT = 1883;

// Authenticated MQTT credentials for ESP32-01
static const char *MQTT_USERNAME = "esp32_01";
static const char *MQTT_PASSWORD = "YOUR_ESP32_01_PASSWORD";
```

### For ESP32-02 (`firmware/esp32_device_02/secrets.h`)

```cpp
#pragma once

static const char *WIFI_SSID = "YOUR_LAB_WIFI_SSID";
static const char *WIFI_PASSWORD = "YOUR_LAB_WIFI_PASSWORD";

// Mosquitto broker host
static const char *MQTT_BROKER_HOST = "10.32.252.85";
static const uint16_t MQTT_BROKER_PORT = 1883;

// Authenticated MQTT credentials for ESP32-02
static const char *MQTT_USERNAME = "esp32_02";
static const char *MQTT_PASSWORD = "YOUR_ESP32_02_PASSWORD";
```

> **Security Note:** `secrets.h` is ignored by Git (`.gitignore`). Never commit or share your real passwords.

---

## 3. How to Compile and Upload Firmware

1. Open Arduino IDE.
2. Select your board: **Tools → Board → ESP32 Arduino → ESP32 Dev Module** (or your specific ESP32 variant).
3. Connect the ESP32 to your PC via USB and select the corresponding COM port (**Tools → Port**).
4. Open `esp32_device_01/esp32_device_01.ino` (or `esp32_device_02/esp32_device_02.ino`).
5. Ensure `secrets.h` is present in the same directory.
6. Click **Upload** (Ctrl + U).
7. Open **Serial Monitor** (Ctrl + Shift + M) at **115200 baud**.

---

## 4. Verifying Successful Connection

When the device powers on, observe the Serial Monitor:

```text
ESP32-01 IoT Security Framework telemetry
Connecting to Wi-Fi SSID: <SSID>
....
WiFi connected
ESP32 IP: 10.32.252.105
Connecting to MQTT broker 10.32.252.85 as user esp32_01 ... connected
Published: {"device_id":"ESP32-01","ip_address":"10.32.252.105","temperature":28.40,"humidity":65.20}
```

The device will automatically publish every 5 seconds and reconnect if Wi-Fi or MQTT drops.

---

## 5. Configuring and Starting the Backend MQTT Collector

The backend collector requires authentication credentials configured in `backend/.env`:

```env
MQTT_BROKER_HOST=10.32.252.85
MQTT_BROKER_PORT=1883
MQTT_TOPIC=iot/esp32/+/sensor
MQTT_CLIENT_ID=iot-security-mqtt-collector
MQTT_USERNAME=iot_collector
MQTT_PASSWORD=YOUR_COLLECTOR_PASSWORD
```

Start the collector from the `backend/` directory:

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m mqtt_collector.collector
```

Expected startup output:

```text
Starting MQTT → PostgreSQL collector
Opening PostgreSQL pool ...
PostgreSQL pool ready
Connecting to MQTT broker 10.32.252.85:1883 (user=iot_collector)
MQTT connected (authenticated as user=iot_collector)
Subscribed to topic: iot/esp32/+/sensor
```

---

## 6. Diagnosing MQTT Authentication Failures

| Symptom | Cause | Diagnostic Steps |
| --- | --- | --- |
| `failed, rc=4` or `failed, rc=5` on ESP32 Serial Monitor | Bad credentials or unauthorized user | Verify `MQTT_USERNAME` and `MQTT_PASSWORD` match `C:\ProgramData\Mosquitto\passwords.txt` and ACL rules in `aclfile.txt`. |
| `FAILED: MQTT_USERNAME or MQTT_PASSWORD missing in secrets.h` | Empty credentials | Fill in `MQTT_USERNAME` and `MQTT_PASSWORD` in `secrets.h`. Anonymous fallback is disabled. |
| Collector error: `MQTT authentication credentials missing` | `MQTT_USERNAME` or `MQTT_PASSWORD` missing in `.env` | Add `MQTT_USERNAME=iot_collector` and `MQTT_PASSWORD=<password>` to `backend/.env`. |
| Collector error: `MQTT authentication failed (username=iot_collector, reason=...)` | Incorrect password or broker permission | Check that user `iot_collector` has read permission for `iot/esp32/+/sensor` in `aclfile.txt`. |
| `failed, rc=-2` on ESP32 | Broker unreachable | Check broker IP address (`10.32.252.85`), ensure port 1883 is open in Windows Firewall, and ensure ESP32 is on the same lab Wi-Fi. |

---

## 7. Notes

- IP is **device-reported** from DHCP (`WiFi.localIP()`), not Nmap-verified.
- Passwords are never logged to console or Serial Monitor.
- Do not commit `secrets.h` or `.env` files.
