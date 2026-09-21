# Setup log

Record every installation. Never mark a tool installed unless a version command succeeded.

Machine: Windows 11 (NT 10.0.26200)
Host user: KIIT
Workspace: `c:\Users\KIIT\Desktop\Web_Project\IOT_Security_Framework`

---

## 2026-08-30 — Workspace inspection (Phase 0)

| Field | Value |
| --- | --- |
| Date | 2026-08-30 |
| Machine | Windows 11 development PC |
| OS | Microsoft Windows NT 10.0.26200.0 |
| Software | Pre-existing toolchain survey (no new installs) |
| Result | Partial: Git, Python 3.13, Node, npm, Cursor present. Several Phase 1 tools missing. |

### Commands and results

| Software | Command | Result |
| --- | --- | --- |
| Git | `git --version` | `git version 2.52.0.windows.1` at `C:\Program Files\Git\cmd\git.exe` |
| Python | `python --version` | `Python 3.13.7` at `C:\Users\KIIT\AppData\Local\Programs\Python\Python313\python.exe` |
| Python launcher | `py -0` | Only 3.13 (64-bit) registered. `py -3.11` failed: no suitable runtime |
| pip | `python -m pip --version` | `pip 25.2` (Python 3.13) |
| Node.js | `node --version` | `v22.19.0` at `C:\Program Files\nodejs\node.exe` |
| npm | `npm --version` | `10.9.3` |
| Docker | `docker --version` | Not recognized. Default install path missing |
| Nmap | `nmap --version` | Not recognized. Default install paths missing |
| PostgreSQL | `psql --version` | Not recognized. `C:\Program Files\PostgreSQL` missing |
| Wireshark | Default `Wireshark.exe` / `tshark.exe` paths | Not found |
| PlatformIO | `pio --version` and `%USERPROFILE%\.platformio\penv\Scripts\pio.exe` | Not found |
| Git repo | `git status` | Not a git repository (initialized later the same day) |
| Cursor | Running this session | Present (version string not exported in this shell) |

### Problem

Master prompt asks for Python 3.11. It is not installed. Python 3.11.16 (2026-08-12) is a source-only security release; python.org no longer ships Windows installers for 3.11 (last installer was 3.11.9).

### Solution

Recorded as Decision D-001. No Python reinstall in Phase 0.

### Verification

Re-run the table above after any future install. Use `scripts/check_windows_prerequisites.ps1` in Phase 1.

---

## Recommended target versions (looked up 2026-08-30)

Use these as install targets. Confirm the live version on the vendor site at install time.

| Tool | Target | Source |
| --- | --- | --- |
| Python | 3.13.7 already on this PC, pending D-001 | Local verify; python.org notes 3.14 is latest feature line, 3.11 is legacy |
| Node.js | Keep 22.19.0 (Maintenance LTS) or optional upgrade to 24.20.0 Active LTS | nodejs.org / endoflife.date |
| PostgreSQL | 18.6 (current stable; 19 is beta) | postgresql.org, 2026-08-13 |
| Nmap | 7.991 | nmap.org/download, 2026-08-06 |
| Docker Desktop | 4.88.1 | Docker Desktop release notes, 2026-08-25 |
| Wireshark | Latest stable from wireshark.org at install time | Not pinned until Phase 1 install |
| PlatformIO | Latest Core from platformio.org at install time | Not pinned until Phase 1 install |
