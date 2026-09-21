# Decision log

## D-001 — Python version for the project

| Field | Value |
| --- | --- |
| Date | 2026-08-30 |
| Status | **Accepted** (2026-08-31) |
| Decision | Use Python 3.13.7 with `backend/.venv` |

### Options considered

1. **Python 3.11.x as written in the master prompt.** Latest 3.11 is 3.11.16 (2026-08-12), but it is security-fixes-only and **source-only**. python.org no longer publishes Windows installers. Last Windows installer was 3.11.9 (April 2024), which is behind current 3.11 security patches. Compiling CPython from source on Windows is not appropriate for this beginner setup.
2. **Python 3.13.7 already installed on this PC.** Verified with `python --version`. Still a supported feature/bugfix line. FastAPI, Pydantic, SQLAlchemy, Pandas, NumPy, and scikit-learn are expected to run on 3.13. Matches "never assume success / record real versions".
3. **Install Python 3.14.x** (python.org current feature series as of this date). Newer than needed; more risk of library lag for ML/SHAP; extra install work.

### Recommended option

**Option 2: keep Python 3.13.7** and create a dedicated project virtual environment from it in Phase 1.

### Reason

The prompt's 3.11 pin is outdated relative to Windows packaging in 2026. Using the already-verified 3.13.7 interpreter avoids an unsupported Windows binary and avoids compiling from source.

### Trade-off

Thesis text that says "Python 3.11" must be updated to "Python 3.13.7" (or whatever we actually use). If an examiner insists on 3.11, we would have to document why official Windows binaries are unavailable.

### Impact

All later `pip install` commands, `venv`, and SETUP_LOG entries use 3.13.7 unless you reject this decision.

### Status update (2026-08-31)

**Accepted** — backend virtual environment created with Python 3.13.7 for the database phase.

---

## D-006 — PostgreSQL over SQLite for persistence

| Field | Value |
| --- | --- |
| Date | 2026-08-31 |
| Status | Accepted |
| Decision | Use PostgreSQL 18+ with SQLAlchemy 2.x, Alembic, and psycopg3 |

### Reason

Production-oriented relational database with JSONB, concurrency, foreign keys, and suitability for M.Tech deployment and audit history.

### Impact

No SQLite fallback. Database setup requires a running PostgreSQL service and `.env` credentials.

---

## D-007 — Approved database schema decisions

| Field | Value |
| --- | --- |
| Date | 2026-08-31 |
| Status | Accepted |
| Decision | Implement the approved 24-table schema with the following choices |

### Choices

1. Keep `services` catalog table plus historical `scan_services` observations.
2. One `findings` row per scan session (simpler v1 model).
3. Risk bands stored in `risk_level_thresholds` for `IDRS-1.0.0` (0–20 LOW … 81–100 CRITICAL).
4. Optional traceability columns: `findings.scan_service_id`, `ml_predictions.risk_score_id`, `risk_factor_values.finding_id`.
5. Device IP/MAC on `devices` is a dashboard snapshot; `device_interfaces` is authoritative per NIC.
6. Initial Alembic migration bootstraps schema via `Base.metadata.create_all()` because autogenerate requires live DB credentials.


## D-002 — Node.js line (recommended: keep 22.19.0)

| Field | Value |
| --- | --- |
| Date | 2026-08-30 |
| Status | Recommended; confirm in Phase 1 Node checkpoint |
| Decision | Node.js version for the future React/Vite dashboard |

### Options considered

1. Keep **v22.19.0** already installed (Maintenance LTS, EOL 2027-04-30).
2. Upgrade to **24.20.0** Active LTS "Krypton" (2026-08-26).
3. Install Current 26.x — not LTS until October 2026; skip for a thesis project.

### Recommended option

Keep 22.19.0 for Phase 1. Upgrade to 24.x only if Vite or a later dependency requires it.

### Reason

It is already verified. Maintenance LTS still receives security fixes. Dashboard code is Phase 17.

### Trade-off

You are one major LTS behind Active. That is acceptable until the frontend is created.

---

## D-003 — Do not scaffold React/Vite/Tailwind in Phase 1

| Field | Value |
| --- | --- |
| Date | 2026-08-30 |
| Status | Accepted for this plan (can revisit) |
| Decision | Phase 1 treats Node/npm as prerequisites only. The Vite app is created in Phase 17. |

### Reason

The master order places the dashboard after FastAPI and PostgreSQL. Creating a frontend now would skip Phases 2–16.

### Trade-off

The Windows checklist item "React/Vite / Tailwind" stays `[ ]` until Phase 17, even if Node is `[x]`.

---

## D-004 — Project root is this workspace, not a nested folder

| Field | Value |
| --- | --- |
| Date | 2026-08-30 |
| Status | Accepted |
| Decision | Use `IOT_Security_Framework\` as the repo root instead of creating `iot-security-framework\` inside it. |

### Reason

Cursor is already opened on this folder. Nesting would duplicate the tree and confuse Git.

---

## D-005 — PostgreSQL target 18.6, Docker Desktop 4.88.1, Nmap 7.991

| Field | Value |
| --- | --- |
| Date | 2026-08-30 |
| Status | Planning target; install in Phase 1 only after each checkpoint |
| Decision | Pin install targets to current stable versions looked up on 2026-08-30. Re-check vendor pages on the install day. |

### Reason

Master prompt: never assume versions. PostgreSQL 19 is still beta. Nmap 7.991 is the current stable Windows installer. Docker Desktop 4.88.1 is the current desktop release noted on 2026-08-25.
