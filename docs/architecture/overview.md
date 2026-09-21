# Architecture overview (beginner)

## The idea

You are building a **defensive** lab platform. It looks at IoT devices you own, records what it finds with evidence, scores risk in an IoT-specific way, and later uses ML only to *assist* that scoring — never to invent findings.

## Four roles

```text
                         WINDOWS 11
              Cursor, Python/FastAPI, PostgreSQL,
              React dashboard, ML, Git, Docker, ESP32 tools
                             │
                       Authorized Lab LAN
              ┌──────────────┴──────────────┐
              │                             │
         KALI LINUX                   RASPBERRY PI
         Nmap / Scapy /               Mosquitto MQTT
         Wireshark / tcpdump          IoT gateway
              │                             │
         Security assessment           MQTT / Wi-Fi
                                            │
                                      ESP32 devices
```

### Windows — development machine (this PC)

Write code, run the API and dashboard, store results, train ML, flash ESP32 firmware. This is your daily workstation.

### Kali Linux — assessment machine

Run network discovery and protocol checks against the **lab** only. If you have one laptop, Kali runs as a virtual machine. Networking mode (NAT vs bridged vs host-only) will be chosen in Phase 2, not now.

### Raspberry Pi — IoT gateway

Runs Mosquitto (MQTT broker). ESP32 devices publish sensor data here. The broker must not be reachable from the public internet.

### ESP32 — targets

Small Wi-Fi boards that pretend to be IoT products. We will flash both a **secure** profile and a **controlled insecure** profile so the scanner has known-good and known-bad cases.

## Data flow (later phases)

```text
ESP32 → Wi-Fi → MQTT → Raspberry Pi → Lab LAN
                                         ↓
                              Kali / Windows scanner
                                         ↓
                              Findings (with evidence)
                                         ↓
                              IDRS risk engine
                                         ↓
                              FastAPI + PostgreSQL
                                         ↓
                              React dashboard
```

## What we are not doing yet

No Kali VM, no Raspberry Pi image, no ESP32 firmware, no Nmap scripts, no FastAPI server, no dashboard in Phase 0/1. Those have their own phases so each piece can be verified.
