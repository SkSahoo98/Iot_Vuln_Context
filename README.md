# AI-Assisted IoT Vulnerability Assessment and IoT Dynamic Risk Scoring Framework

Defensive M.Tech project: discover and assess **owned / authorized lab** IoT devices, compute an IoT Dynamic Risk Score (IDRS), assist ranking with ML, and show explainable results on a dashboard.

This is **not** a tool for scanning the public internet or systems you do not own.

## What this platform will do

1. Discover IoT devices on the authorized lab LAN.
2. Fingerprint devices and services.
3. Assess ports, protocols, authentication, encryption, and IoT-specific weaknesses.
4. Map reliable findings to CVE/CWE/CVSS where evidence supports it.
5. Calculate an IoT-specific Dynamic Risk Score (IDRS), not a renamed CVSS.
6. Use ML to assist risk classification/prioritization.
7. Explain why a score was assigned (SHAP / factor contribution).
8. Recommend remediation and keep scan/risk history.
9. Present results in a React dashboard and reproducible reports.

## Architecture in plain language

Think of four machines with four jobs:

| Machine | Job |
| --- | --- |
| **Windows 11** (this PC) | Main development: Cursor, Python API, database, React dashboard, ML, Git, Docker, ESP32 tooling |
| **Kali Linux** (VM if you have only one laptop) | Security assessment tools: Nmap, Scapy, Wireshark, tcpdump, OpenSSL |
| **Raspberry Pi** | IoT gateway and MQTT broker (Mosquitto). Not exposed to the public internet |
| **ESP32 boards** | Lab target devices with Wi-Fi + MQTT, using controlled secure and insecure configs |

Windows talks to the lab LAN. Kali assesses devices you own. The Pi is the MQTT hub. ESP32s are the things being assessed.

## Current phase

See `PROJECT_STATUS.md`. Work follows the master plan in `IoT_Security_Framework_Master_Prompt.md`.

**Do not skip phases.** Hardware lab (Kali, Pi, ESP32) comes before scanners, risk scoring, ML, and the dashboard.

## Safety

Only assess:

- Devices you own
- Your isolated IoT lab
- Systems with explicit authorization

Any active security test is **authorized lab-only**.

## Project records

| File | Purpose |
| --- | --- |
| `PROJECT_STATUS.md` | Phase, milestone, blockers, next task |
| `SETUP_LOG.md` | Every install: version, command, result |
| `DECISION_LOG.md` | Why we chose an option |
| `EXPERIMENT_LOG.md` | Reproducible experiments |
| `TROUBLESHOOTING.md` | Problems and fixes |
| `CHANGELOG.md` | Meaningful changes by date |

## Quick start (after Phase 1)

Commands will be added only after the Windows toolchain is verified. Do not assume installs succeeded until they are recorded in `SETUP_LOG.md`.

## MQTT → PostgreSQL collector

Collects DHT22 readings from Mosquitto and inserts them into `sensor_data` (existing schema only).

### Install dependencies

```powershell
cd c:\Users\KIIT\Desktop\Web_Project\IOT_Security_Framework\backend
.\.venv\Scripts\Activate.ps1
pip install -r mqtt_collector\requirements.txt
```

### Configure environment

Ensure the project root `.env` (or `backend\.env`) contains at least:

```env
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=iot_security
POSTGRES_USER=postgres
POSTGRES_PASSWORD=YOUR_REAL_PASSWORD

MQTT_BROKER_HOST=10.84.237.85
MQTT_BROKER_PORT=1883
MQTT_TOPIC=iot/esp32/+/sensor
```

Copy defaults from `backend\.env.example` if needed. Never commit real passwords.

### Run the collector

```powershell
cd c:\Users\KIIT\Desktop\Web_Project\IOT_Security_Framework\backend
.\.venv\Scripts\Activate.ps1
python -m mqtt_collector.collector
```

Expected log lines when a device publishes:

```text
MQTT connected
Message received
Device: ESP32-01
Temperature: 30.40 C
Humidity: 76.90 %
Database insert successful
```

Stop with `Ctrl+C` (graceful shutdown).

### Verify in PostgreSQL

```powershell
psql -U postgres -d iot_security -c "SELECT device_id, temperature, humidity, timestamp FROM sensor_data ORDER BY timestamp DESC LIMIT 5;"
psql -U postgres -d iot_security -c "SELECT device_id, status, updated_at FROM devices;"
```
