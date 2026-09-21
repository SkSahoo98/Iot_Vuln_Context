# ESP32 firmware (lab devices)

These sketches publish DHT22 telemetry **and the device's current Wi-Fi IP**
(`WiFi.localIP()`) to Mosquitto.

| Device | Folder | Topic | `device_id` |
| --- | --- | --- | --- |
| ESP32-01 | `esp32_device_01/` | `iot/esp32/01/sensor` | `ESP32-01` |
| ESP32-02 | `esp32_device_02/` | `iot/esp32/02/sensor` | `ESP32-02` |

## Libraries

- WiFi (ESP32 core)
- PubSubClient
- DHT sensor library (Adafruit DHT)

## Setup

1. Copy `secrets.h.example` → `secrets.h` in the device folder.
2. Set lab Wi-Fi SSID/password and MQTT broker host.
3. Flash the matching sketch.
4. Confirm Serial Monitor:

```text
WiFi connected
ESP32 IP: <DHCP address>
Published: {"device_id":"ESP32-01","ip_address":"...","temperature":...,"humidity":...}
```

5. Restart the MQTT collector so it stores `devices.ip_address`.

## Notes

- IP is **device-reported** from DHCP (`WiFi.localIP()`), not Nmap-verified.
- Do not commit `secrets.h`.
- Do not hard-code ESP32 IP addresses in firmware or the dashboard.
