# AUDIT_NOW — Current State (12 Oct 2026)

Read-only audit. No source code was changed. Secrets were not printed.

Live checks performed during this audit:

| Check | Result |
|---|---|
| PostgreSQL `iot_security` | Reachable. Tables: `devices` (2), `sensor_data` (14,296), `experiments` (1), `experiment_results` (3). No `alembic_version` table. |
| Latest telemetry | ESP32-01 2026-09-19 14:45, ESP32-02 2026-09-19 14:44 (IST). 364 rows are 0/0. |
| MQTT broker `10.84.237.85` | Port 1883 NOT reachable, port 8883 NOT reachable |
| Ollama `127.0.0.1:11434` | Up, model `qwen3:8b` |
| Nmap / TShark on this host | Installed: Nmap 7.99, TShark 4.6.8, Npcap present. **Not called by any application code.** |
| `pytest --collect-only` (backend) | Collects 8 tests from `tests/test_database.py`. Not executed (one test writes to the DB). |
| `risk_engine/tests/*.py` | Run as print scripts. 0 `test_` functions, 0 `assert` statements. |
| Secrets in git | `.env` and `secrets.h` are not tracked |

---

## 1. Current working components

| Component | What works | Verified how |
|---|---|---|
| ESP32 firmware (01, 02) | DHT22 read, skips NaN and 0/0, publishes JSON (`device_id`, temperature, humidity, `ip_address`) every 5 s to `iot/esp32/0X/sensor`; optional MQTT username/password | Code inspection; historical rows in DB |
| MQTT collector | paho-mqtt v2, subscribes `iot/esp32/+/sensor`, validates payload, rejects unknown devices and 0/0, inserts `sensor_data`, updates `devices.ip_address`, 15 s CONNACK timeout, auto-reconnect | Code inspection; 14,296 rows in DB |
| Device inventory API | `GET /api/v1/devices` derives ONLINE / OFFLINE / UNKNOWN from latest valid telemetry (30 s window), ignores stored `status` | Read-only query + earlier live call |
| Risk engine IoT-RISK-v1 | Deterministic score, weights validated at import, per-factor contributions, version string | In-memory reproduction (67.5 / 82.5 / 47.5 / 57.5 / 12.5 / 100 / 50) |
| AI explanation | Ollama `/api/chat`, `format=json`, `think=false`, temperature 0.2; strict grounding prompt; output validation; deterministic fallback; in-memory cache | Live call earlier (≈102 s, `source=ollama`) |
| Experiments API | `GET /experiments`, `GET /experiments/{id}` via ORM `Experiment` / `ExperimentResult` (these 2 ORM models match the live tables exactly) | Read-only query |
| Frontend | Read-only dashboard: Overview, Devices, Findings, Risk & Research, AI; calls only the 7 GET endpoints | Code inspection |

**Runtime database schema (source of truth):** `database/schema.sql` (`devices`, `sensor_data`) + `database/experiment_schema.sql` (`experiments`, `experiment_results`).

| Table | Key columns | Accessed by |
|---|---|---|
| `devices` | `id` BIGSERIAL, `device_id` (unique), `ip_address` INET, `mac_address`, `device_type`, `firmware_version`, `status`, `created_at`, `updated_at` | `mqtt_collector/collector.py` (SELECT, UPDATE), `app/services/device_service.py` (raw SQL SELECT) |
| `sensor_data` | `id`, `device_id` FK → `devices.device_id`, `temperature`, `humidity`, `timestamp` | `collector.py` (INSERT), `device_service.py` (SELECT) |
| `experiments` | `id` UUID, `experiment_name`, `objective`, `hypothesis`, `methodology`, `parameters` JSONB, `status`, `conclusion`, … | `app/services/experiment_service.py` (ORM), `scripts/record_context_experiment.py` (upsert) |
| `experiment_results` | `id` UUID, `experiment_id` FK, `metric_name`, `metric_value`, `notes` | same as above |

Database connection: API uses `DATABASE_URL` (`app/core/database.py`); collector uses `POSTGRES_*` or `DATABASE_URL` (`mqtt_collector/config.py`).

---

## 2. Broken components

| # | Component | Problem | File |
|---|---|---|---|
| B1 | MQTT findings | Reported even when the broker is unreachable. Both HIGH findings are always returned because they are driven by config flags, not observation. | `backend/app/services/finding_service.py` |
| B2 | Alembic | Two root revisions (`0001_initial_schema`, `b7c4e2a91d30`, both `down_revision=None`), so there are multiple heads. `upgrade()` = `Base.metadata.create_all` (24-table UUID design, incompatible with BIGSERIAL `devices`). `downgrade()` = `drop_all`, which **would drop live `devices`, `experiments`, `experiment_results`**. Never run Alembic against the live DB. | `backend/alembic/versions/0001_initial_schema.py`, `backend/alembic/versions/b7c4e2a91d30_initial_schema.py` |
| B3 | DB tests | Expect 24 tables, an `admin` user, `Device.device_name`, ESP32-02 at 192.168.1.22, score 76. None of these exist in the live DB, so the suite would fail. One test attempts an INSERT. | `backend/tests/test_database.py`, `backend/tests/conftest.py` |
| B4 | Risk "tests" | Print scripts, no assertions; `test_mqtt_risk.py` uses its own context (0.8 / 0.6) and prints 78.0, not the API's 67.5 | `risk_engine/tests/test_mqtt_risk.py`, `risk_engine/tests/test_context_experiment.py` |
| B5 | Stored device status | Collector only ever writes `ONLINE`; column is stale (both rows say ONLINE; API correctly derives OFFLINE) | `backend/mqtt_collector/collector.py` |
| B6 | Collector stability | Sep 19 logs showed "MQTT disconnected (Unspecified error)" about every 2 s, probably a duplicate `MQTT_CLIENT_ID` (two collector instances). **Not re-verifiable now: broker is down.** | `backend/mqtt_collector/config.py` |

---

## 3. Configuration-based components (NOT real detections)

| Item | Comes from | Used by | Effect |
|---|---|---|---|
| `MQTT_WITHOUT_TLS` finding | `.env` `MQTT_TLS_ENABLED=false` + `MQTT_BROKER_PORT=1883` | `finding_service.py` → `scanner/mqtt_checks/mqtt_analyzer.py::check_mqtt_without_tls` | Finding exists if port==1883 and flag is false |
| `MQTT_ANONYMOUS_ACCESS` finding | `.env` `MQTT_ANONYMOUS_ALLOWED=true` | `mqtt_analyzer.py::check_mqtt_anonymous_access` | Finding exists if flag is true |
| Evidence `service`, `version`, `observed_topics` | `.env` `MQTT_SERVICE_NAME`, `MQTT_SERVICE_VERSION`, `MQTT_OBSERVED_TOPICS` | `mqtt_analyzer.py::analyze_mqtt` | Displayed as evidence, never observed |
| Context `authentication_security`, `protocol_security` | Same two `.env` flags | `backend/app/services/risk_service.py` → `risk_engine/features/iot_context.py::build_mqtt_context` | Double counting: same fact creates the finding and raises its context |
| Context `device_criticality`, `network_exposure`, `firmware_security` | `.env` `RISK_*` = 0.3 / 0.3 / 0.5 | `risk_service.py` | One global context for all findings, so every finding scores the same |
| `devices.firmware_version` = `1.0.0` | Seed in `database/schema.sql` | `device_service.py` | Not reported by firmware |
| Experiment metrics 67.5 / 82.5 / 15.0 | Typed constants | `backend/scripts/record_context_experiment.py` | Not computed by the engine |
| Remediation text | Static strings | `mqtt_analyzer.py` | No playbook, no execution |
| Attack scenario text (known findings) | Fixed deterministic text (deliberate grounding choice) | `backend/app/services/ai_explanation.py` | Acceptable; labelled "potential" |

Pipeline as it really runs today:

```text
.env flags ─► finding_service.list_findings ─► mqtt_analyzer.analyze_mqtt (if-rules) ─► FindingOut (not stored)
.env flags + RISK_* ─► risk_service.assess_risk ─► build_mqtt_context ─► calculate_dynamic_risk ─► RiskSummaryOut (not stored)
finding + risk ─► ai_explanation.explain_finding ─► Ollama or fallback ─► AIExplanationOut
```

Classification: **B (configuration/environment)** for both MQTT findings. No network or protocol observation occurs.

---

## 4. Missing components

| # | Missing | Notes |
|---|---|---|
| M1 | Active MQTT probe | No code connects to the broker for assessment. Collector connects only to ingest telemetry; its CONNACK is never recorded as evidence. |
| M2 | Assessment status | No COMPLETE / INCOMPLETE concept; unreachable broker is not handled. |
| M3 | Evidence persistence | No tables for assessment runs, evidence, findings, risk snapshots. |
| M4 | Write / trigger API | All routes are GET; CORS `allow_methods=["GET"]` in `backend/app/main.py`. |
| M5 | Remediation execution and verification | No playbook, confirmation, re-assessment, or before/after comparison. Frontend `RemediationList.tsx` only renders strings. |
| M6 | Mosquitto configs | No insecure/secure broker config in repo; `configs/` is empty. |
| M7 | TLS support | Collector has no `tls_set`; firmware uses plain `WiFiClient`. |
| M8 | Nmap / TShark integration | Tools installed on host, but no code invokes them; no XML/pcap parsing; no stored artifacts. |
| M9 | Tests | No API, MQTT, scanner, AI-grounding, or valid risk tests. |
| M10 | Firmware version reporting | Not in payload. |

Not needed before 15 Oct: ML/SHAP (`ml/`), Raspberry Pi (`raspberry_pi/`), ESP32-03, empty `scanner/*` subfolders, 22 unused ORM models.

---

## 5. Exact files responsible

| Area | Files |
|---|---|
| Config / env | `backend/app/core/config.py`, `backend/.env.example`, local `.env` (not tracked) |
| API routes / CORS | `backend/app/api/v1.py`, `backend/app/main.py` |
| Findings | `backend/app/services/finding_service.py`, `scanner/mqtt_checks/mqtt_analyzer.py` |
| Context + risk | `backend/app/services/risk_service.py`, `risk_engine/features/iot_context.py`, `risk_engine/scoring/dynamic_risk.py`, `risk_engine/rules/risk_rules.py` |
| AI | `backend/app/services/ai_explanation.py` |
| Devices / telemetry | `backend/app/services/device_service.py`, `backend/mqtt_collector/collector.py`, `backend/mqtt_collector/config.py` |
| Live schema | `database/schema.sql`, `database/experiment_schema.sql` |
| Experiments | `backend/app/services/experiment_service.py`, `backend/app/models/experiment.py`, `backend/scripts/record_context_experiment.py` |
| Obsolete / unused (do not use) | `backend/app/models/{device,scan,finding,risk,remediation,ml,user}.py`, `backend/alembic/versions/*.py`, `backend/scripts/seed_data.py`, `backend/scripts/setup_database.py` (Alembic path), `backend/tests/test_database.py`, `backend/tests/conftest.py` |
| Firmware | `firmware/esp32_device_01/esp32_device_01.ino`, `firmware/esp32_device_02/esp32_device_02.ino`, `secrets.h.example` (x2) |
| Frontend API | `frontend/src/api/security.ts`, `frontend/src/api/client.ts`, `frontend/src/api/types.ts` |

Risk engine facts (unchanged, for reference): `score = sev×100×0.5 + context×100×0.5`; severity INFO 0 / LOW 0.25 / MEDIUM 0.5 / HIGH 0.75 / CRITICAL 1.0; factor weights criticality 0.30, exposure 0.20, auth 0.20, protocol 0.20, firmware 0.10; levels <20 LOW, <40 MODERATE, <60 MEDIUM, <80 HIGH, ≥80 CRITICAL; version `IoT-RISK-v1`. Known weaknesses: double counting, global static context, `firmware_security` where higher means more risk, INFO + max context = 50 MEDIUM, no persistence, no automated tests.

AI facts: endpoint `OLLAMA_BASE_URL/api/chat`, model `qwen3:8b`, timeout 180 s, input = one finding + its evidence + its risk item, output = 7-field JSON. Rejects CVE IDs, 13 banned overclaim phrases, and any `risk_explanation` missing the exact score/level. Fallback is deterministic. Cache is in memory (600 s / 45 s). Classification: **C — explains authoritative findings.** It does not detect and does not calculate risk.

---

## 6. Critical blockers

| # | Blocker | Blocks | Where |
|---|---|---|---|
| C1 | **Lab MQTT broker unreachable** (1883 and 8883 closed/filtered from this host) | Collecting any real evidence; end-to-end demo | Lab environment (not a repo file). Broker host is set in local `.env` `MQTT_BROKER_HOST`. |
| C2 | Findings are config-asserted | Every claim of "detected" | `backend/app/services/finding_service.py` |
| C3 | No persistence of runs / evidence / findings / risk | Before/after comparison | `database/` (needs a new additive SQL file) |
| C4 | GET-only API | Starting an assessment, re-assessment | `backend/app/api/v1.py`, `backend/app/main.py` |
| C5 | Alembic `downgrade()` would drop live tables | Data safety | `backend/alembic/versions/*.py`. Rule: **do not run Alembic.** |

C1 does not block writing code. It blocks verifying real evidence. Code can be developed with the probe correctly returning `INCOMPLETE` while the broker is down.

---

## 7. Recommended implementation order

1. **Active MQTT probe** (new `scanner/mqtt_checks/mqtt_probe.py`, uses existing `paho-mqtt` + stdlib `socket`/`ssl`):
   - TCP reachability on 1883 and 8883, with timeouts.
   - MQTT CONNECT without credentials, using a unique client ID; record the CONNACK reason code (accepted / not authorized / bad credentials).
   - TLS handshake on 8883: record protocol version, cipher and certificate subject/expiry, or "no TLS listener".
   - Optional service info from `$SYS/broker/version`, read only if the anonymous connection was accepted, and recorded as observed.
   - Returns a raw evidence dict with timestamps. No publish, no brute force, allowlisted host only.
2. **Evidence-driven findings and assessment status:**
   - `finding_service.py` uses probe evidence instead of the `.env` flags.
   - Broker unreachable → status `INCOMPLETE` and zero MQTT findings.
   - `MQTT_ANONYMOUS_ACCESS` only if CONNACK accepted without credentials.
   - `MQTT_WITHOUT_TLS` only if a plaintext MQTT session on 1883 was accepted.
   - The risk context is fed from the same observed evidence. Double counting is documented as a known limitation, not redesigned now.
3. **Persistence plus trigger API:**
   - Additive `database/assessment_schema.sql` with `assessment_runs`, `assessment_evidence`, `assessment_findings` (holding a risk snapshot), using the existing `schema.sql` style with no Alembic.
   - `POST /api/v1/assessments`, `GET /api/v1/assessments`, `GET /api/v1/assessments/{id}`; CORS allows POST.
4. **Remediation and re-assessment:**
   - Commit Mosquitto insecure and secure configs (`allow_anonymous false` + `password_file`) under `configs/mosquitto/`.
   - Deterministic remediation playbook per finding.
   - Collector and firmware credentials via existing `.env` / `secrets.h` support.
   - `POST /api/v1/assessments/{id}/reassess` + `GET /api/v1/assessments/compare?before=&after=` returns resolved findings and risk change.
5. **Tests plus minimal UI and AI hookup:**
   - pytest for the probe (mocked broker), the finding rules, risk-engine assertions and compare logic.
   - AI explains a finding from a stored run (guardrails unchanged).
   - Frontend gets one "Run assessment" button and a before/after panel. No styling work.
