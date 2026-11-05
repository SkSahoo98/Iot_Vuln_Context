"""Secure Live IoT Telemetry Publisher — Local PostgreSQL to Neon.

Transfers sanitized ESP32 DHT22 sensor readings from local PostgreSQL to Neon PostgreSQL
so production devices (ESP32-01, ESP32-02) display fresh telemetry and ONLINE status.

Usage:
    # Dry-run (Default — Zero writes to Neon):
    python backend/scripts/publish_telemetry_to_neon.py --dry-run

    # Catch-up (Publish last 2-3 minutes of readings once):
    python backend/scripts/publish_telemetry_to_neon.py --catchup

    # Live Mode (Continuous sync loop every 10 seconds):
    python backend/scripts/publish_telemetry_to_neon.py --live
"""

from __future__ import annotations

import argparse
import atexit
import os
import signal
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

# Ensure backend root is importable
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings
from app.services.telemetry_sanitizer import (
    ALLOWED_DEVICE_IDS,
    TelemetryReading,
    filter_and_validate_batch,
)

LOCK_FILE_PATH = BACKEND_ROOT / ".telemetry_publisher.lock"


class SingleInstanceLock:
    """Cross-platform non-blocking file lock to prevent concurrent publisher processes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._file = None

    def acquire(self) -> bool:
        try:
            self._file = open(self.path, "w")
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._file.write(str(os.getpid()))
            self._file.flush()
            return True
        except (OSError, BlockingIOError):
            return False

    def release(self) -> None:
        if self._file:
            try:
                if os.name == "nt":
                    import msvcrt
                    self._file.seek(0)
                    msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
                self._file.close()
            except Exception:
                pass
            try:
                if self.path.exists():
                    self.path.unlink()
            except Exception:
                pass
            self._file = None


def mask_conninfo(url: str | None) -> str:
    """Mask credentials in a PostgreSQL connection string for safe terminal display."""
    if not url:
        return "<unset>"
    if "@" in url:
        prefix, host_part = url.split("@", 1)
        scheme_user = prefix.split(":", 1)[0]
        return f"{scheme_user}:****@{host_part.split('?')[0]}"
    return "postgresql://****"


def get_local_connection():
    """Connect read-only to local PostgreSQL."""
    settings = get_settings()
    local_url = settings.database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    return psycopg.connect(local_url, row_factory=dict_row)


def get_neon_connection(neon_url: str):
    """Connect to Neon PostgreSQL over SSL."""
    clean_url = neon_url.replace("postgresql+psycopg://", "postgresql://", 1)
    if "sslmode=" not in clean_url:
        separator = "&" if "?" in clean_url else "?"
        clean_url = f"{clean_url}{separator}sslmode=require"
    return psycopg.connect(clean_url, row_factory=dict_row)


def get_neon_watermarks_and_keys(
    neon_url: str,
    lookback_window: timedelta = timedelta(minutes=15),
) -> tuple[dict[str, datetime], set[tuple[str, datetime]]]:
    """Query Neon for MAX(timestamp) per device and collect recent timestamps for deduplication."""
    watermarks: dict[str, datetime] = {dev: datetime.min.replace(tzinfo=UTC) for dev in ALLOWED_DEVICE_IDS}
    recent_keys: set[tuple[str, datetime]] = set()

    with get_neon_connection(neon_url) as conn:
        with conn.cursor() as cur:
            # 1. High watermarks per device
            cur.execute(
                """
                SELECT device_id, MAX(timestamp) as max_ts
                FROM sensor_data
                WHERE device_id = ANY(%s)
                GROUP BY device_id
                """,
                (list(ALLOWED_DEVICE_IDS),),
            )
            for row in cur.fetchall():
                if row["max_ts"]:
                    watermarks[row["device_id"]] = row["max_ts"].astimezone(UTC)

            # 2. Collect recent timestamps to avoid duplicates
            cutoff = datetime.now(UTC) - lookback_window
            cur.execute(
                """
                SELECT device_id, timestamp
                FROM sensor_data
                WHERE device_id = ANY(%s) AND timestamp >= %s
                """,
                (list(ALLOWED_DEVICE_IDS), cutoff),
            )
            for row in cur.fetchall():
                ts = row["timestamp"].astimezone(UTC)
                recent_keys.add((row["device_id"], ts))

    return watermarks, recent_keys


def fetch_local_telemetry_batch(
    since_timestamps: dict[str, datetime] | None = None,
    lookback_window: timedelta | None = None,
    limit_per_device: int = 100,
) -> list[dict[str, Any]]:
    """Query local PostgreSQL for sensor readings."""
    readings: list[dict[str, Any]] = []

    with get_local_connection() as conn:
        with conn.cursor() as cur:
            for dev in sorted(ALLOWED_DEVICE_IDS):
                if since_timestamps and dev in since_timestamps:
                    min_ts = since_timestamps[dev]
                elif lookback_window:
                    min_ts = datetime.now(UTC) - lookback_window
                else:
                    min_ts = datetime.now(UTC) - timedelta(minutes=3)

                cur.execute(
                    """
                    SELECT device_id, temperature, humidity, timestamp
                    FROM sensor_data
                    WHERE device_id = %s
                      AND timestamp > %s
                      AND NOT (temperature = 0 AND humidity = 0)
                    ORDER BY timestamp ASC
                    LIMIT %s
                    """,
                    (dev, min_ts, limit_per_device),
                )
                readings.extend(cur.fetchall())

    return readings


def insert_telemetry_into_neon(
    neon_url: str,
    readings: list[TelemetryReading],
) -> int:
    """Insert sanitized readings into Neon in an atomic batch transaction.

    Uses an exact device_id + timestamp existence check to guarantee duplicate protection.
    """
    if not readings:
        return 0

    inserted_count = 0
    with get_neon_connection(neon_url) as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                for r in readings:
                    cur.execute(
                        """
                        INSERT INTO sensor_data (device_id, temperature, humidity, timestamp)
                        SELECT %s, %s, %s, %s
                        WHERE NOT EXISTS (
                            SELECT 1 FROM sensor_data
                            WHERE device_id = %s AND timestamp = %s
                        )
                        RETURNING id
                        """,
                        (r.device_id, r.temperature, r.humidity, r.timestamp, r.device_id, r.timestamp),
                    )
                    if cur.fetchone():
                        inserted_count += 1

    return inserted_count


def run_dry_run(neon_url: str | None) -> int:
    """Execute dry-run without writing any records."""
    print("\n" + "=" * 70)
    print("   IoT Security Framework — Telemetry Publisher (DRY-RUN)")
    print("=" * 70)
    print("Mode: DRY-RUN ONLY (Zero writes to Neon)")

    raw_local = fetch_local_telemetry_batch(lookback_window=timedelta(minutes=3))
    print(f"[+] Local PostgreSQL: Retrieved {len(raw_local)} raw readings from last 3 minutes.")

    watermarks: dict[str, datetime] = {}
    neon_keys: set[tuple[str, datetime]] = set()

    if neon_url:
        print(f"[+] Connecting to Neon endpoint: {mask_conninfo(neon_url)}")
        try:
            watermarks, neon_keys = get_neon_watermarks_and_keys(neon_url)
            for dev, wm in watermarks.items():
                wm_str = wm.isoformat() if wm != datetime.min.replace(tzinfo=UTC) else "No readings recorded"
                print(f"    - Neon Watermark for {dev}: {wm_str}")
        except Exception as exc:
            print(f"[-] Could not connect to Neon: {exc.__class__.__name__}")
    else:
        print("[-] NEON_DATABASE_URL not set (skipping remote watermark check).")

    # Validate and filter
    valid_readings, duplicates, invalids = filter_and_validate_batch(raw_local, existing_keys=neon_keys)

    by_device: dict[str, list[TelemetryReading]] = {dev: [] for dev in ALLOWED_DEVICE_IDS}
    for r in valid_readings:
        by_device[r.device_id].append(r)

    print("-" * 70)
    print("Telemetry Extraction Summary:")
    for dev in sorted(ALLOWED_DEVICE_IDS):
        print(f"  {dev}: {len(by_device[dev])} eligible readings ready for sync")
    print(f"  Duplicates Detected: {duplicates}")
    print(f"  Invalid / Glitched:  {invalids}")
    print(f"  Total Eligible:      {len(valid_readings)}")

    if valid_readings:
        print("\nSanitized Sample (first 3 readings):")
        for s in valid_readings[:3]:
            print(f"    Device: {s.device_id} | Temp: {s.temperature:.2f} C | Hum: {s.humidity:.2f} % | Time: {s.timestamp.isoformat()}")

    print("-" * 70)
    print("*** DRY-RUN ONLY: ZERO PRODUCTION WRITES OCCURRED ***")
    print("Run with '--catchup' or '--live' and set NEON_DATABASE_URL to publish.")
    return 0


def run_catchup(neon_url: str) -> int:
    """Publish only the most recent 2-3 minutes of readings once."""
    print("\n" + "=" * 70)
    print("   IoT Security Framework — Telemetry Publisher (INITIAL CATCH-UP)")
    print("=" * 70)
    print(f"[+] Target Neon Database: {mask_conninfo(neon_url)}")

    watermarks, neon_keys = get_neon_watermarks_and_keys(neon_url, lookback_window=timedelta(minutes=5))
    raw_local = fetch_local_telemetry_batch(since_timestamps=watermarks, lookback_window=timedelta(minutes=3))

    valid_readings, duplicates, invalids = filter_and_validate_batch(raw_local, existing_keys=neon_keys)
    print(f"[+] Extracted {len(raw_local)} local readings ({duplicates} duplicates, {invalids} invalid).")

    if not valid_readings:
        print("[+] Neon is already up to date with recent local telemetry. Nothing to insert.")
        return 0

    print(f"[+] Inserting {len(valid_readings)} sanitized readings into Neon...")
    inserted = insert_telemetry_into_neon(neon_url, valid_readings)
    print(f"[+] CATCH-UP COMPLETE: Successfully inserted {inserted} readings into Neon PostgreSQL.")

    for dev in sorted(ALLOWED_DEVICE_IDS):
        dev_readings = [r for r in valid_readings if r.device_id == dev]
        if dev_readings:
            latest = max(r.timestamp for r in dev_readings)
            print(f"    - {dev}: {len(dev_readings)} readings published (Latest timestamp: {latest.isoformat()})")

    return 0


def run_live_loop(neon_url: str, interval_seconds: int = 10) -> int:
    """Continuously poll local PostgreSQL and sync new readings to Neon."""
    print("\n" + "=" * 70)
    print("   IoT Security Framework — Live Telemetry Publisher (CONTINUOUS)")
    print("=" * 70)
    print(f"[+] Target Neon Database: {mask_conninfo(neon_url)}")
    print(f"[+] Sync Interval: every {interval_seconds} seconds")
    print("[+] Press Ctrl+C to stop.\n")

    stopping = False

    def _sig_handler(sig, frame):  # noqa: ARG001
        nonlocal stopping
        print("\n[!] Shutdown signal received. Stopping live telemetry publisher...")
        stopping = True

    signal.signal(signal.SIGINT, _sig_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sig_handler)

    # Initial watermark fetch
    try:
        watermarks, recent_keys = get_neon_watermarks_and_keys(neon_url)
    except Exception as exc:
        print(f"[-] Initial connection to Neon failed: {exc}")
        return 1

    while not stopping:
        loop_start = time.time()
        try:
            raw_local = fetch_local_telemetry_batch(since_timestamps=watermarks)
            valid_readings, duplicates, _ = filter_and_validate_batch(raw_local, existing_keys=recent_keys)

            if valid_readings:
                inserted = insert_telemetry_into_neon(neon_url, valid_readings)
                for r in valid_readings:
                    recent_keys.add((r.device_id, r.timestamp))
                    if r.timestamp > watermarks.get(r.device_id, datetime.min.replace(tzinfo=UTC)):
                        watermarks[r.device_id] = r.timestamp

                now_str = datetime.now().strftime("%H:%M:%S")
                counts_str = ", ".join(
                    f"{dev}: {sum(1 for r in valid_readings if r.device_id == dev)}"
                    for dev in sorted(ALLOWED_DEVICE_IDS)
                )
                print(f"[{now_str}] Synced {inserted} new readings ({counts_str}).")
            else:
                now_str = datetime.now().strftime("%H:%M:%S")
                # Clean heartbeat log
                print(f"[{now_str}] Up to date. Waiting for next batch...")

            # Prune recent_keys older than 20 minutes to prevent memory unbounded growth
            prune_cutoff = datetime.now(UTC) - timedelta(minutes=20)
            recent_keys = {k for k in recent_keys if k[1] >= prune_cutoff}

        except psycopg.OperationalError as exc:
            now_str = datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] Temporary connection error: {exc.__class__.__name__}. Retrying next interval...")
        except Exception as exc:
            now_str = datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] Error during sync cycle: {exc}")

        # Sleep remaining time until next interval
        elapsed = time.time() - loop_start
        sleep_time = max(0.5, interval_seconds - elapsed)
        time.sleep(sleep_time)

    print("[+] Telemetry publisher exited cleanly.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Secure Live IoT Telemetry Publisher to Neon")
    parser.add_argument("--dry-run", action="store_true", help="Dry run only (default: True)")
    parser.add_argument("--catchup", action="store_true", help="Publish recent 2-3 minutes of readings once")
    parser.add_argument("--live", action="store_true", help="Run continuous sync loop every 10 seconds")
    parser.add_argument("--interval", type=int, default=10, help="Polling interval in seconds for live mode")
    parser.add_argument("--neon-url", type=str, default=None, help="Neon PostgreSQL URL (defaults to NEON_DATABASE_URL)")
    args = parser.parse_args()

    neon_url = args.neon_url or os.getenv("NEON_DATABASE_URL")

    # Enforce single-instance lock for live or catchup modes
    if args.catchup or args.live:
        lock = SingleInstanceLock(LOCK_FILE_PATH)
        if not lock.acquire():
            print("[-] ERROR: Another instance of the telemetry publisher is already running. Aborting.")
            return 1
        atexit.register(lock.release)

    if args.live:
        if not neon_url:
            print("[-] ERROR: Live mode requires NEON_DATABASE_URL environment variable.")
            return 1
        return run_live_loop(neon_url, interval_seconds=args.interval)

    if args.catchup:
        if not neon_url:
            print("[-] ERROR: Catch-up mode requires NEON_DATABASE_URL environment variable.")
            return 1
        return run_catchup(neon_url)

    # Default to dry-run
    return run_dry_run(neon_url)


if __name__ == "__main__":
    raise SystemExit(main())

