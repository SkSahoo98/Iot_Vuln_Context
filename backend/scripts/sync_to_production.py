"""Automatic Real-Time IoT Synchronization Service — Local PostgreSQL to Neon.

Continuously and securely synchronizes:
1. Worker A (Telemetry): Fresh ESP32-01 & ESP32-02 sensor readings into Neon sensor_data.
2. Worker B (Assessments): Newly completed security assessments, findings, evidence,
   and risk snapshots into Neon assessment tables.

Guarantees:
- In-memory sanitization (zero private IPs, internal paths, raw args, credentials or tokens).
- Independent worker failure isolation (telemetry and assessment workers never block each other).
- Single-instance concurrency lock.
- Duplicate-protected transactional inserts.
- Exponential backoff and auto-recovery from transient connection outages.
- Graceful shutdown on SIGINT/SIGTERM.

Usage:
    # Dry-run (Default — Zero writes to Neon):
    python backend/scripts/sync_to_production.py --dry-run

    # Initial Catch-up (One-shot sync of recent telemetry and un-synced assessments):
    python backend/scripts/sync_to_production.py --catchup

    # Live Continuous Synchronization Service:
    python backend/scripts/sync_to_production.py --live
"""

from __future__ import annotations

import argparse
import atexit
import os
import signal
import sys
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

# Ensure backend root is importable
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings
from app.services.sanitizer import (
    sanitize_assessment_record,
    validate_sanitized_data,
)
from app.services.telemetry_sanitizer import (
    ALLOWED_DEVICE_IDS,
    TelemetryReading,
    filter_and_validate_batch,
)

SYNC_LOCK_FILE = BACKEND_ROOT / ".sync_to_production.lock"


class SingleInstanceLock:
    """Cross-platform non-blocking file lock to prevent concurrent sync instances."""

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
    """Mask credentials in a connection string for safe logging."""
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


# ==============================================================================
# WORKER A: TELEMETRY SYNC LOGIC
# ==============================================================================

class TelemetryWorker:
    """Synchronizes sanitized ESP32 sensor telemetry from local PostgreSQL to Neon."""

    def __init__(self, neon_url: str) -> None:
        self.neon_url = neon_url
        self.watermarks: dict[str, datetime] = {dev: datetime.min.replace(tzinfo=UTC) for dev in ALLOWED_DEVICE_IDS}
        self.recent_keys: set[tuple[str, datetime]] = set()

    def refresh_watermarks(self) -> None:
        """Fetch Neon watermarks and recent keys for deduplication."""
        with get_neon_connection(self.neon_url) as conn:
            with conn.cursor() as cur:
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
                        self.watermarks[row["device_id"]] = row["max_ts"].astimezone(UTC)

                cutoff = datetime.now(UTC) - timedelta(minutes=15)
                cur.execute(
                    """
                    SELECT device_id, timestamp
                    FROM sensor_data
                    WHERE device_id = ANY(%s) AND timestamp >= %s
                    """,
                    (list(ALLOWED_DEVICE_IDS), cutoff),
                )
                for row in cur.fetchall():
                    self.recent_keys.add((row["device_id"], row["timestamp"].astimezone(UTC)))

    def sync_cycle(self, lookback_window: timedelta | None = None) -> int:
        """Execute one telemetry sync pass. Returns number of inserted rows."""
        readings_to_check: list[dict[str, Any]] = []

        with get_local_connection() as conn:
            with conn.cursor() as cur:
                for dev in sorted(ALLOWED_DEVICE_IDS):
                    if lookback_window:
                        min_ts = datetime.now(UTC) - lookback_window
                    else:
                        min_ts = self.watermarks.get(dev, datetime.min.replace(tzinfo=UTC))

                    cur.execute(
                        """
                        SELECT device_id, temperature, humidity, timestamp
                        FROM sensor_data
                        WHERE device_id = %s
                          AND timestamp > %s
                          AND NOT (temperature = 0 AND humidity = 0)
                        ORDER BY timestamp ASC
                        LIMIT 100
                        """,
                        (dev, min_ts),
                    )
                    readings_to_check.extend(cur.fetchall())

        valid_readings, _, _ = filter_and_validate_batch(readings_to_check, existing_keys=self.recent_keys)
        if not valid_readings:
            return 0

        inserted_count = 0
        with get_neon_connection(self.neon_url) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    for r in valid_readings:
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
                            self.recent_keys.add((r.device_id, r.timestamp))
                            if r.timestamp > self.watermarks.get(r.device_id, datetime.min.replace(tzinfo=UTC)):
                                self.watermarks[r.device_id] = r.timestamp

        # Prune deduplication keys older than 25 minutes
        cutoff = datetime.now(UTC) - timedelta(minutes=25)
        self.recent_keys = {k for k in self.recent_keys if k[1] >= cutoff}

        return inserted_count


# ==============================================================================
# WORKER B: ASSESSMENT SYNC LOGIC
# ==============================================================================

class AssessmentWorker:
    """Synchronizes completed security assessments from local PostgreSQL to Neon."""

    def __init__(self, neon_url: str, allowed_ids: list[UUID] | None = None) -> None:
        self.neon_url = neon_url
        self.allowed_ids = allowed_ids
        self.published_ids: set[str] = set()

    def refresh_published_ids(self) -> None:
        """Fetch list of assessment IDs already present in Neon."""
        with get_neon_connection(self.neon_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM assessment_runs")
                self.published_ids = {str(row["id"]) for row in cur.fetchall()}

    def get_candidate_local_assessments(self) -> list[dict[str, Any]]:
        """Fetch local COMPLETE assessment runs.

        If self.allowed_ids is provided, selects ONLY those exact local UUIDs.
        Ensures NO fallback to the historical assessment queue.
        """
        if self.allowed_ids is not None:
            if not self.allowed_ids:
                return []
            with get_local_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, target, assessment_type, status, started_at, completed_at,
                               error_summary, metadata, created_at
                        FROM assessment_runs
                        WHERE id = ANY(%s)
                        """,
                        (self.allowed_ids,),
                    )
                    found_rows = {row["id"]: row for row in cur.fetchall()}

            candidates: list[dict[str, Any]] = []
            for uid in self.allowed_ids:
                if uid not in found_rows:
                    print(f"[-] Assessment {uid} does not exist in local database (skipping).")
                    continue
                row = found_rows[uid]
                if row["status"] != "COMPLETE":
                    print(f"[-] Assessment {uid} has status '{row['status']}' (expected 'COMPLETE'). Skipping.")
                    continue
                if str(uid) in self.published_ids:
                    print(f"[*] Assessment {uid} is already published in Neon (skipping without modification).")
                    continue
                candidates.append(row)
            return candidates

        # Default fallback for live continuous service (recently completed runs only)
        with get_local_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, target, assessment_type, status, started_at, completed_at,
                           error_summary, metadata, created_at
                    FROM assessment_runs
                    WHERE status = 'COMPLETE'
                      AND completed_at >= NOW() - INTERVAL '24 hours'
                    ORDER BY started_at ASC
                    """
                )
                runs = cur.fetchall()
        return [r for r in runs if str(r["id"]) not in self.published_ids]

    def sync_assessment(self, assessment_id: UUID) -> tuple[bool, str | None]:
        """Fetch, sanitize, validate, and publish a single assessment in one atomic Neon transaction.

        Returns:
            (success: bool, clean_target: str | None)
        """
        with get_local_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM assessment_runs WHERE id = %s", (assessment_id,))
                run = cur.fetchone()
                if not run:
                    return False, None

                cur.execute("SELECT * FROM assessment_evidence WHERE assessment_id = %s ORDER BY observed_at, id", (assessment_id,))
                evidence = cur.fetchall()

                cur.execute("SELECT * FROM assessment_findings WHERE assessment_id = %s ORDER BY created_at, id", (assessment_id,))
                findings = cur.fetchall()

                cur.execute("SELECT * FROM risk_snapshots WHERE assessment_id = %s ORDER BY created_at, id", (assessment_id,))
                risks = cur.fetchall()

        # In-memory sanitization
        clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(
            run, evidence, findings, risks
        )

        # Validation check
        violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
        if violations:
            print(f"[-] Assessment {assessment_id} rejected by sanitization validation:")
            for v in violations:
                print(f"    ! {v}")
            return False, None

        # Atomic Neon transaction
        with get_neon_connection(self.neon_url) as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO assessment_runs (
                            id, target, assessment_type, status,
                            started_at, completed_at, error_summary, metadata, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                        """,
                        (
                            clean_run["id"], clean_run["target"], clean_run["assessment_type"],
                            clean_run["status"], clean_run["started_at"], clean_run["completed_at"],
                            clean_run.get("error_summary"), psycopg.types.json.Jsonb(clean_run["metadata"]),
                            clean_run["created_at"],
                        ),
                    )

                    for ev in clean_ev:
                        cur.execute(
                            """
                            INSERT INTO assessment_evidence (
                                id, assessment_id, target, port,
                                check_type, result, evidence_source, observation, observed_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO NOTHING
                            """,
                            (
                                ev["id"], ev["assessment_id"], ev["target"], ev.get("port"),
                                ev["check_type"], ev["result"], ev["evidence_source"],
                                psycopg.types.json.Jsonb(ev["observation"]), ev["observed_at"],
                            ),
                        )

                    for f in clean_f:
                        cur.execute(
                            """
                            INSERT INTO assessment_findings (
                                id, assessment_id, finding_id, finding_type, category,
                                title, severity, confidence, description, target, port,
                                evidence_reference, remediation, status, created_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO NOTHING
                            """,
                            (
                                f["id"], f["assessment_id"], f["finding_id"], f["finding_type"],
                                f["category"], f["title"], f["severity"], f.get("confidence"),
                                f.get("description"), f["target"], f.get("port"),
                                f.get("evidence_reference"), f.get("remediation"), f["status"],
                                f["created_at"],
                            ),
                        )

                    for r in clean_r:
                        cur.execute(
                            """
                            INSERT INTO risk_snapshots (
                                id, assessment_id, finding_ref, score, risk_level,
                                score_version, base_severity, context_score,
                                factor_contributions, context_inputs, created_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO NOTHING
                            """,
                            (
                                r["id"], r["assessment_id"], r.get("finding_ref"), r["score"],
                                r["risk_level"], r["score_version"], r.get("base_severity"),
                                r.get("context_score"), psycopg.types.json.Jsonb(r["factor_contributions"]),
                                psycopg.types.json.Jsonb(r["context_inputs"]), r["created_at"],
                            ),
                        )

        self.published_ids.add(str(assessment_id))
        return True, clean_run["target"]

    def sync_cycle(self) -> int:
        """Check for and publish un-synced local completed assessments."""
        candidates = self.get_candidate_local_assessments()
        published_count = 0
        for cand in candidates:
            cand_id = cand["id"]
            success, clean_target = self.sync_assessment(cand_id)
            if success:
                published_count += 1
                now_str = datetime.now().strftime("%H:%M:%S")
                print(f"[{now_str}] [AssessmentWorker] Published assessment {cand_id} ({clean_target}).")
        return published_count


# ==============================================================================
# DRY-RUN AND ORCHESTRATION
# ==============================================================================

def parse_assessment_ids(ids_arg: str | None) -> list[UUID] | None:
    """Parse and validate comma-separated assessment UUID strings."""
    if ids_arg is None:
        return None
    cleaned_ids: list[UUID] = []
    for raw in ids_arg.split(","):
        token = raw.strip()
        if not token:
            continue
        try:
            cleaned_ids.append(UUID(token))
        except ValueError as exc:
            print(f"[-] ERROR: Invalid assessment UUID '{token}': {exc}")
            raise ValueError(f"Invalid assessment UUID '{token}': {exc}") from exc
    return cleaned_ids


def run_dry_run(neon_url: str | None, assessment_ids: list[UUID] | None = None) -> int:
    """Inspect local data and Neon watermarks without performing any writes."""
    print("\n" + "=" * 70)
    print("   IoT Security Framework — Production Sync Service (DRY-RUN)")
    print("=" * 70)
    print("Mode: DRY-RUN ONLY (Zero writes to Neon)\n")

    # --- Worker A Inspection ---
    print("[1] Inspecting Worker A: Telemetry Synchronization")
    local_settings = get_settings()
    local_clean = mask_conninfo(local_settings.database_url)
    print(f"    - Source: Local PostgreSQL ({local_clean})")

    neon_watermarks: dict[str, datetime] = {}
    neon_recent_keys: set[tuple[str, datetime]] = set()

    if neon_url:
        neon_clean = mask_conninfo(neon_url)
        print(f"    - Target: Neon PostgreSQL ({neon_clean})")
        try:
            with get_neon_connection(neon_url) as conn:
                with conn.cursor() as cur:
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
                            neon_watermarks[row["device_id"]] = row["max_ts"].astimezone(UTC)

                    cutoff = datetime.now(UTC) - timedelta(minutes=15)
                    cur.execute(
                        """
                        SELECT device_id, timestamp
                        FROM sensor_data
                        WHERE device_id = ANY(%s) AND timestamp >= %s
                        """,
                        (list(ALLOWED_DEVICE_IDS), cutoff),
                    )
                    for row in cur.fetchall():
                        neon_recent_keys.add((row["device_id"], row["timestamp"].astimezone(UTC)))
        except Exception as exc:
            print(f"    [-] Could not connect to Neon for telemetry check: {exc.__class__.__name__}")
    else:
        print("    [-] NEON_DATABASE_URL not set (skipping remote watermark comparison).")

    # Fetch candidate local readings (last 3 minutes)
    candidate_telemetry: list[dict[str, Any]] = []
    with get_local_connection() as conn:
        with conn.cursor() as cur:
            for dev in sorted(ALLOWED_DEVICE_IDS):
                min_ts = neon_watermarks.get(dev, datetime.now(UTC) - timedelta(minutes=3))
                cur.execute(
                    """
                    SELECT device_id, temperature, humidity, timestamp
                    FROM sensor_data
                    WHERE device_id = %s
                      AND timestamp > %s
                      AND NOT (temperature = 0 AND humidity = 0)
                    ORDER BY timestamp ASC
                    LIMIT 100
                    """,
                    (dev, min_ts),
                )
                candidate_telemetry.extend(cur.fetchall())

    valid_tel, dup_tel, invalid_tel = filter_and_validate_batch(candidate_telemetry, existing_keys=neon_recent_keys)
    tel_by_device = Counter(r.device_id for r in valid_tel)

    print(f"    - Planned Telemetry Inserts (Lookback 3m): {len(valid_tel)} valid readings")
    for dev in sorted(ALLOWED_DEVICE_IDS):
        wm_str = neon_watermarks.get(dev, "None")
        print(f"      * {dev}: {tel_by_device.get(dev, 0)} new rows to insert (Neon watermark: {wm_str})")

    # --- Worker B Inspection ---
    print("\n[2] Inspecting Worker B: Assessment Synchronization")
    neon_published_ids: set[str] = set()
    if neon_url:
        try:
            with get_neon_connection(neon_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM assessment_runs")
                    neon_published_ids = {str(row["id"]) for row in cur.fetchall()}
            print(f"    - Existing Neon Assessment Runs: {len(neon_published_ids)}")
        except Exception as exc:
            print(f"    [-] Could not connect to Neon for assessment check: {exc.__class__.__name__}")

    planned_runs = 0
    planned_findings = 0
    planned_evidence = 0
    planned_snapshots = 0

    if assessment_ids:
        print(f"    - Explicit Assessment Allowlist: {len(assessment_ids)} UUIDs requested")
        with get_local_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, target, assessment_type, status, started_at, completed_at, error_summary, metadata, created_at
                    FROM assessment_runs
                    WHERE id = ANY(%s)
                    """,
                    (assessment_ids,),
                )
                found_map = {row["id"]: row for row in cur.fetchall()}

        for uid in assessment_ids:
            if uid not in found_map:
                print(f"      [-] {uid}: NOT FOUND in local database")
                continue
            run = found_map[uid]
            if run["status"] != "COMPLETE":
                print(f"      [-] {uid}: REJECTED (status: '{run['status']}', expected 'COMPLETE')")
                continue
            if str(uid) in neon_published_ids:
                print(f"      [*] {uid}: ALREADY PUBLISHED in Neon (skipping without modification)")
                continue

            # Fetch child records to inspect sanitization & count planned inserts
            with get_local_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM assessment_evidence WHERE assessment_id = %s ORDER BY observed_at, id", (uid,))
                    evidence = cur.fetchall()
                    cur.execute("SELECT * FROM assessment_findings WHERE assessment_id = %s ORDER BY created_at, id", (uid,))
                    findings = cur.fetchall()
                    cur.execute("SELECT * FROM risk_snapshots WHERE assessment_id = %s ORDER BY created_at, id", (uid,))
                    risks = cur.fetchall()

            clean_run, clean_ev, clean_f, clean_r = sanitize_assessment_record(run, evidence, findings, risks)
            violations = validate_sanitized_data(clean_run, clean_ev, clean_f, clean_r)
            if violations:
                print(f"      [-] {uid}: VALIDATION FAILED:")
                for v in violations:
                    print(f"          ! {v}")
                continue

            planned_runs += 1
            planned_findings += len(clean_f)
            planned_evidence += len(clean_ev)
            planned_snapshots += len(clean_r)
            print(f"      [+] {uid}: ELIGIBLE TO PUBLISH")
            print(f"          * Sanitized Target: {clean_run['target']}")
            print(f"          * Type: {clean_run['assessment_type']} | Status: {clean_run['status']}")
            print(f"          * Planned: 1 run, {len(clean_f)} findings, {len(clean_ev)} evidence, {len(clean_r)} risk snapshots")

    else:
        print("    - No explicit --assessment-ids provided.")
        with get_local_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, target, assessment_type, status, completed_at
                    FROM assessment_runs
                    WHERE status = 'COMPLETE'
                    ORDER BY completed_at DESC
                    LIMIT 5
                    """
                )
                sample = cur.fetchall()
        print("    - Sample of 5 latest complete local assessments:")
        for s in sample:
            in_neon = "In Neon" if str(s["id"]) in neon_published_ids else "Ready to sync"
            print(f"      * {s['id']} | {s['target']} | {s['assessment_type']} | {in_neon}")

    # --- Summary Banner ---
    print("\n" + "=" * 70)
    print("*** DRY-RUN ONLY: ZERO PRODUCTION WRITES OCCURRED ***")
    print("Planned Neon Inserts:")
    print(f"  - Assessment Runs:      {planned_runs}")
    print(f"  - Assessment Findings:  {planned_findings}")
    print(f"  - Assessment Evidence:  {planned_evidence}")
    print(f"  - Risk Snapshots:       {planned_snapshots}")
    print(f"  - Telemetry Readings:   {len(valid_tel)}")
    print(f"Total Database Rows to Insert: {planned_runs + planned_findings + planned_evidence + planned_snapshots + len(valid_tel)}")
    print("=" * 70)
    return 0


def run_catchup(neon_url: str, assessment_ids: list[UUID] | None = None) -> int:
    """Execute one-shot initial sync of recent telemetry and un-synced completed assessments."""
    print("\n" + "=" * 70)
    print("   IoT Security Framework — Production Sync Service (CATCH-UP)")
    print("=" * 70)
    print(f"[+] Target Neon Database: {mask_conninfo(neon_url)}")

    # 1. Catchup Worker B (Assessments)
    print("\n--- Synchronizing Assessments ---")
    assessment_worker = AssessmentWorker(neon_url, allowed_ids=assessment_ids)
    assessment_worker.refresh_published_ids()
    published_a = assessment_worker.sync_cycle()
    print(f"[+] Assessment Sync Complete: {published_a} assessments published to Neon.")

    # 2. Catchup Worker A (Telemetry)
    print("\n--- Synchronizing Telemetry ---")
    telemetry_worker = TelemetryWorker(neon_url)
    telemetry_worker.refresh_watermarks()
    inserted_t = telemetry_worker.sync_cycle(lookback_window=timedelta(minutes=3))
    print(f"[+] Telemetry Sync Complete: {inserted_t} sensor readings published to Neon.")

    print("\n[+] Initial catch-up completed successfully.")
    return 0


def run_live_service(
    neon_url: str,
    telemetry_interval: int = 10,
    assessment_interval: int = 30,
    assessment_ids: list[UUID] | None = None,
) -> int:
    """Run permanent dual-worker synchronization service in background/interactive mode."""
    print("\n" + "=" * 70)
    print("   IoT Security Framework — Live Production Sync Service")
    print("=" * 70)
    print(f"[+] Target Neon Database: {mask_conninfo(neon_url)}")
    print(f"[+] Worker A (Telemetry): interval {telemetry_interval}s")
    print(f"[+] Worker B (Assessments): interval {assessment_interval}s")
    print("[+] Press Ctrl+C to terminate.\n")

    stopping = False

    def _sig_handler(sig, frame):  # noqa: ARG001
        nonlocal stopping
        print("\n[!] Shutdown signal received. Stopping synchronization service...")
        stopping = True

    signal.signal(signal.SIGINT, _sig_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sig_handler)

    telemetry_worker = TelemetryWorker(neon_url)
    assessment_worker = AssessmentWorker(neon_url, allowed_ids=assessment_ids)

    # Initial setup
    try:
        telemetry_worker.refresh_watermarks()
        assessment_worker.refresh_published_ids()
    except Exception as exc:
        print(f"[-] Initial connection to Neon failed: {exc}")
        return 1

    last_assessment_check = 0.0
    backoff_delay = 5.0

    while not stopping:
        now_time = time.time()
        now_str = datetime.now().strftime("%H:%M:%S")

        # 1. Run Worker A (Telemetry)
        try:
            t_inserted = telemetry_worker.sync_cycle()
            if t_inserted > 0:
                print(f"[{now_str}] [Worker A: Telemetry] Synced {t_inserted} new sensor readings.")
            backoff_delay = 5.0  # Reset backoff on success
        except psycopg.OperationalError as exc:
            print(f"[{now_str}] [Worker A: Telemetry] Connection error: {exc.__class__.__name__}. Backing off {backoff_delay}s...")
            time.sleep(backoff_delay)
            backoff_delay = min(60.0, backoff_delay * 1.5)
            continue
        except Exception as exc:
            print(f"[{now_str}] [Worker A: Telemetry] Error: {exc}")

        # 2. Run Worker B (Assessments)
        if (now_time - last_assessment_check) >= assessment_interval:
            last_assessment_check = now_time
            try:
                a_synced = assessment_worker.sync_cycle()
                if a_synced > 0:
                    print(f"[{now_str}] [Worker B: Assessments] Synced {a_synced} completed assessments.")
            except psycopg.OperationalError as exc:
                print(f"[{now_str}] [Worker B: Assessments] Connection error: {exc.__class__.__name__}.")
            except Exception as exc:
                print(f"[{now_str}] [Worker B: Assessments] Error: {exc}")

        time.sleep(telemetry_interval)

    print("[+] Synchronization service stopped gracefully.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="IoT Security Framework — Production Sync Service")
    parser.add_argument("--dry-run", action="store_true", help="Dry run only (default: True)")
    parser.add_argument("--catchup", action="store_true", help="Perform initial catch-up sync once")
    parser.add_argument("--live", action="store_true", help="Run continuous live background sync service")
    parser.add_argument("--assessment-ids", type=str, default=None, help="Comma-separated list of local assessment UUIDs to sync")
    parser.add_argument("--telemetry-interval", type=int, default=10, help="Telemetry poll interval in seconds")
    parser.add_argument("--assessment-interval", type=int, default=30, help="Assessment poll interval in seconds")
    parser.add_argument("--neon-url", type=str, default=None, help="Neon PostgreSQL URL (defaults to NEON_DATABASE_URL)")
    args = parser.parse_args()

    try:
        assessment_ids = parse_assessment_ids(args.assessment_ids)
    except ValueError:
        return 1

    neon_url = args.neon_url or os.getenv("NEON_DATABASE_URL")

    if args.catchup or args.live:
        lock = SingleInstanceLock(SYNC_LOCK_FILE)
        if not lock.acquire():
            print("[-] ERROR: Another instance of the production sync service is already running. Aborting.")
            return 1
        atexit.register(lock.release)

    if args.live:
        if not neon_url:
            print("[-] ERROR: Live mode requires NEON_DATABASE_URL environment variable.")
            return 1
        return run_live_service(
            neon_url,
            telemetry_interval=args.telemetry_interval,
            assessment_interval=args.assessment_interval,
            assessment_ids=assessment_ids,
        )

    if args.catchup:
        if not neon_url:
            print("[-] ERROR: Catch-up mode requires NEON_DATABASE_URL environment variable.")
            return 1
        return run_catchup(neon_url, assessment_ids=assessment_ids)

    # Default to dry-run
    return run_dry_run(neon_url, assessment_ids=assessment_ids)


if __name__ == "__main__":
    raise SystemExit(main())

