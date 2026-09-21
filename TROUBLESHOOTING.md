# Troubleshooting

No issues resolved yet beyond the Phase 0 survey.

## Template

```text
Problem:
Symptoms:
Root cause:
Solution:
Verification:
Prevention:
```

---

## Open notes (not yet failures)

### Python 3.11 not installed on Windows

- **Symptoms:** `py -3.11 --version` reports no suitable runtime. Only Python 3.13 is registered.
- **Root cause (current understanding):** 3.11 was never installed on this PC. Upstream 3.11 is also past the Windows-installer stage.
- **Solution:** Decision D-001 (pending). Do not compile 3.11 from source as the first Path.
- **Verification:** After D-001, `python --version` inside the project venv.
- **Prevention:** Pin the interpreter in SETUP_LOG and README so later sessions do not assume 3.11.
