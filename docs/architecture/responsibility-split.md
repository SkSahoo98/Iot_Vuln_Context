# Responsibility split

Confirmed from the master plan. Do not move a tool to a different machine without recording a decision.

## Windows 11 — main development

- Cursor
- Python (see Decision D-001)
- Git
- Node.js LTS + npm
- React / Vite / Tailwind (app scaffold in Phase 17; Node is a Phase 1 prerequisite)
- FastAPI, Uvicorn, Pydantic, SQLAlchemy, Alembic
- PostgreSQL
- Docker Desktop
- Nmap (also on Kali; Windows copy is for local/dev checks)
- Wireshark
- PlatformIO / Arduino IDE
- ML libraries (Pandas, NumPy, scikit-learn, XGBoost, SHAP)

## Kali Linux — security assessment (Phase 2)

- Nmap, Scapy, Wireshark, tcpdump, OpenSSL, Netcat, Python

If only one laptop is available: Kali as a VM. NAT vs bridged vs host-only will be explained before any VM network change.

## Raspberry Pi — IoT gateway (Phase 3)

- Raspberry Pi OS
- Mosquitto MQTT broker
- MQTT clients
- Optional gateway services
- Must stay off the public internet

## ESP32 — IoT targets (Phase 4)

- Wi-Fi, MQTT, HTTP/HTTPS where needed
- TLS and authentication (secure profile)
- Device ID and firmware version
- Controlled insecure lab profile for experiments
