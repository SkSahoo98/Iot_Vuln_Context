# Windows prerequisites (Phase 1)

Survey date: 2026-08-30. A box is `[x]` only after a version command succeeded on this PC.

| Item | Status | Verified version / note |
| --- | --- | --- |
| Git | [x] | 2.52.0.windows.1 |
| Python 3.11 | [ ] | Not installed. See Decision D-001. Python 3.13.7 is present |
| Python venv | [ ] | Not created yet |
| Cursor | [x] | In use for this project |
| Node.js LTS | [x] | v22.19.0 (Maintenance LTS). Active LTS is 24.20.0 — Decision D-002 |
| npm | [x] | 10.9.3 |
| React / Vite | [ ] | Deferred to Phase 17 (Decision D-003). Node is the Phase 1 prerequisite |
| Tailwind | [ ] | Deferred to Phase 17 |
| PostgreSQL | [ ] | Target 18.6 at install time |
| Docker Desktop | [ ] | Target 4.88.1 at install time |
| Nmap | [ ] | Target 7.991 at install time |
| Wireshark | [ ] | Latest stable at install time |
| PlatformIO | [ ] | Not installed |
| ESP32 board support | [ ] | After PlatformIO |

Phase 1 installs missing tools **one checkpoint at a time**. Do not install the whole list in one sitting.
