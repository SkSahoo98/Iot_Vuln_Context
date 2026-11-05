"""Secure Local Assessment Publisher to Production Neon PostgreSQL.

Transfers an already completed local vulnerability assessment into the production
Neon PostgreSQL database with strict in-memory sanitization, multi-layer validation,
and explicit operator confirmation.

Usage:
    # Dry-run (Default - No writes to Neon):
    python backend/scripts/publish_assessment_to_neon.py --assessment-id a921b260-f51d-4f16-9b9f-9acc11decc26 --dry-run

    # Explicit Publishing (Requires NEON_DATABASE_URL and interactive confirmations):
    python backend/scripts/publish_assessment_to_neon.py --assessment-id a921b260-f51d-4f16-9b9f-9acc11decc26 --publish
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
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
    SanitizationError,
    sanitize_assessment_record,
    validate_sanitized_data,
)


def mask_conninfo(url: str) -> str:
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
    # Ensure psycopg-compatible protocol prefix
    clean_url = neon_url.replace("postgresql+psycopg://", "postgresql://", 1)
    if "sslmode=" not in clean_url:
        separator = "&" if "?" in clean_url else "?"
        clean_url = f"{clean_url}{separator}sslmode=require"
    return psycopg.connect(clean_url, row_factory=dict_row)


def fetch_local_assessment(
    assessment_id: UUID,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch complete assessment and child records from local PostgreSQL."""
    with get_local_connection() as conn:
        with conn.cursor() as cur:
            # 1. Fetch Run
            cur.execute("SELECT * FROM assessment_runs WHERE id = %s", (assessment_id,))
            run = cur.fetchone()
            if not run:
                raise ValueError(f"Assessment {assessment_id} not found in local PostgreSQL.")

            # 2. Fetch Evidence
            cur.execute(
                "SELECT * FROM assessment_evidence WHERE assessment_id = %s ORDER BY observed_at, id",
                (assessment_id,),
            )
            evidence = cur.fetchall()

            # 3. Fetch Findings
            cur.execute(
                "SELECT * FROM assessment_findings WHERE assessment_id = %s ORDER BY created_at, id",
                (assessment_id,),
            )
            findings = cur.fetchall()

            # 4. Fetch Risk Snapshots
            cur.execute(
                "SELECT * FROM risk_snapshots WHERE assessment_id = %s ORDER BY created_at, id",
                (assessment_id,),
            )
            risks = cur.fetchall()

    return run, evidence, findings, risks


def check_neon_assessment_exists(neon_url: str, assessment_id: UUID) -> bool:
    """Check if the assessment already exists in Neon without modifying anything."""
    try:
        with get_neon_connection(neon_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM assessment_runs WHERE id = %s", (assessment_id,))
                row = cur.fetchone()
                return row is not None
    except Exception as exc:
        print(f"[-] Note: Could not query Neon ({exc.__class__.__name__}).")
        return False


def publish_to_neon(
    neon_url: str,
    run: dict[str, Any],
    evidence: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    risks: list[dict[str, Any]],
) -> dict[str, int]:
    """Insert sanitized assessment records into Neon in a single transaction."""
    counts = {"run": 0, "evidence": 0, "findings": 0, "risks": 0}

    with get_neon_connection(neon_url) as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                # 1. Insert assessment_runs
                cur.execute(
                    """
                    INSERT INTO assessment_runs (
                        id, target, assessment_type, status,
                        started_at, completed_at, error_summary, metadata, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    RETURNING id
                    """,
                    (
                        run["id"],
                        run["target"],
                        run["assessment_type"],
                        run["status"],
                        run["started_at"],
                        run["completed_at"],
                        run.get("error_summary"),
                        json.dumps(run["metadata"]),
                        run["created_at"],
                    ),
                )
                if cur.fetchone():
                    counts["run"] += 1

                # 2. Insert assessment_evidence
                for ev in evidence:
                    cur.execute(
                        """
                        INSERT INTO assessment_evidence (
                            id, assessment_id, target, port,
                            check_type, result, evidence_source, observation, observed_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                        RETURNING id
                        """,
                        (
                            ev["id"],
                            ev["assessment_id"],
                            ev["target"],
                            ev.get("port"),
                            ev["check_type"],
                            ev["result"],
                            ev["evidence_source"],
                            json.dumps(ev["observation"]),
                            ev["observed_at"],
                        ),
                    )
                    if cur.fetchone():
                        counts["evidence"] += 1

                # 3. Insert assessment_findings
                for f in findings:
                    cur.execute(
                        """
                        INSERT INTO assessment_findings (
                            id, assessment_id, finding_id, finding_type, category,
                            title, severity, confidence, description, target, port,
                            evidence_reference, remediation, status, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                        RETURNING id
                        """,
                        (
                            f["id"],
                            f["assessment_id"],
                            f["finding_id"],
                            f["finding_type"],
                            f["category"],
                            f["title"],
                            f["severity"],
                            f.get("confidence"),
                            f.get("description"),
                            f["target"],
                            f.get("port"),
                            f.get("evidence_reference"),
                            f.get("remediation"),
                            f["status"],
                            f["created_at"],
                        ),
                    )
                    if cur.fetchone():
                        counts["findings"] += 1

                # 4. Insert risk_snapshots
                for r in risks:
                    cur.execute(
                        """
                        INSERT INTO risk_snapshots (
                            id, assessment_id, finding_ref, score, risk_level,
                            score_version, base_severity, context_score,
                            factor_contributions, context_inputs, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                        RETURNING id
                        """,
                        (
                            r["id"],
                            r["assessment_id"],
                            r.get("finding_ref"),
                            r["score"],
                            r["risk_level"],
                            r["score_version"],
                            r.get("base_severity"),
                            r.get("context_score"),
                            json.dumps(r["factor_contributions"]),
                            json.dumps(r["context_inputs"]),
                            r["created_at"],
                        ),
                    )
                    if cur.fetchone():
                        counts["risks"] += 1

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish local assessment to Neon PostgreSQL")
    parser.add_argument(
        "--assessment-id",
        type=UUID,
        default=UUID("a921b260-f51d-4f16-9b9f-9acc11decc26"),
        help="UUID of the assessment to publish",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run only (default: True unless --publish is explicitly given)",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Execute actual publication after explicit confirmation",
    )
    parser.add_argument(
        "--target-alias",
        type=str,
        default="lab-mqtt-broker",
        help="Logical asset target alias for sanitized cloud display",
    )
    parser.add_argument(
        "--neon-url",
        type=str,
        default=None,
        help="Optional Neon PostgreSQL URL (defaults to NEON_DATABASE_URL env var)",
    )
    args = parser.parse_args()

    is_publish_mode = bool(args.publish)
    neon_url = args.neon_url or os.getenv("NEON_DATABASE_URL")

    print("=" * 70)
    print("   IoT Security Framework — Secure Local Assessment Publisher")
    print("=" * 70)
    print(f"Mode: {'PUBLISH TO NEON' if is_publish_mode else 'DRY-RUN (READ-ONLY)'}")
    print(f"Target Assessment ID: {args.assessment_id}")

    # Step 1: Read local assessment
    try:
        raw_run, raw_evidence, raw_findings, raw_risks = fetch_local_assessment(args.assessment_id)
    except Exception as exc:
        print(f"[-] ERROR: Failed to load local assessment: {exc}")
        return 1

    print(f"[+] Loaded local assessment '{args.assessment_id}' successfully.")
    print(f"    - Original Target: {raw_run['target']}")
    print(f"    - Status: {raw_run['status']}")
    print(f"    - Completed At: {raw_run['completed_at']}")
    print(f"    - Findings: {len(raw_findings)}")
    print(f"    - Evidence: {len(raw_evidence)}")
    print(f"    - Risk Snapshots: {len(raw_risks)}")

    # Step 2: In-Memory Sanitization
    clean_run, clean_evidence, clean_findings, clean_risks = sanitize_assessment_record(
        raw_run, raw_evidence, raw_findings, raw_risks, canonical_target=args.target_alias
    )
    print("[+] In-memory sanitization completed.")

    # Step 3: Strong Recursive Validation
    violations = validate_sanitized_data(clean_run, clean_evidence, clean_findings, clean_risks)
    if violations:
        print("[-] SANITIZATION VALIDATION FAILED:")
        for v in violations:
            print(f"    ! {v}")
        print("[-] Publishing halted. Data does not satisfy security invariants.")
        return 1

    print("[+] Sanitization validation: 100% PASSED (zero sensitive patterns detected).")

    # Group findings by severity
    severity_counts = Counter(f["severity"] for f in clean_findings)
    overall_risk = next((r for r in clean_risks if r.get("finding_ref") is None), None)

    # Check Neon existence if URL available
    neon_exists = False
    if neon_url:
        print(f"[+] Connecting to Neon endpoint: {mask_conninfo(neon_url)}")
        neon_exists = check_neon_assessment_exists(neon_url, args.assessment_id)
        if neon_exists:
            print(f"[!] Assessment '{args.assessment_id}' ALREADY EXISTS in Neon.")
        else:
            print(f"[+] Assessment '{args.assessment_id}' is NOT yet present in Neon.")
    else:
        print("[-] NEON_DATABASE_URL not set in process environment (skipping cloud check).")

    # Display Summary
    print("-" * 70)
    print("Assessment Publishing Summary:")
    print(f"  Assessment ID:      {clean_run['id']}")
    print(f"  Sanitized Target:   {clean_run['target']}")
    print(f"  Status:             {clean_run['status']}")
    print(f"  Completed Date:     {clean_run['completed_at']}")
    print(f"  Findings Total:     {len(clean_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity_counts[sev]:
            print(f"    - {sev}: {severity_counts[sev]}")
    print(f"  Evidence Records:   {len(clean_evidence)}")
    print(f"  Risk Snapshots:     {len(clean_risks)}")
    if overall_risk:
        print(f"  Overall Risk Score: {overall_risk['score']} ({overall_risk['risk_level']})")
    print(f"  Sanitization:       Cleaned private IPs, paths, and raw args")
    print("-" * 70)

    # Handle Dry-run
    if not is_publish_mode:
        print("\n*** DRY-RUN ONLY: NO PRODUCTION WRITES OCCURRED ***")
        print("To publish this assessment, run with '--publish' and provide NEON_DATABASE_URL.")
        return 0

    # Publishing flow
    if not neon_url:
        print("[-] ERROR: Cannot publish without NEON_DATABASE_URL environment variable.")
        return 1

    if neon_exists:
        print("[-] ABORTED: Assessment already exists in Neon PostgreSQL.")
        print("    Conflict policy preserves existing data. No updates permitted.")
        return 0

    # Explicit confirmation prompts
    print("\nWARNING: You are about to publish this sanitized assessment to production Neon.")
    try:
        conf1 = input("Approve publishing this assessment to production Neon? (yes/no): ").strip().lower()
        if conf1 not in ("yes", "y"):
            print("[-] Publication cancelled by operator.")
            return 0

        conf2 = input(f"Type the assessment UUID '{args.assessment_id}' to confirm: ").strip()
        if conf2 != str(args.assessment_id):
            print("[-] Confirmation UUID did not match. Publication cancelled.")
            return 0
    except EOFError:
        print("\n[-] Non-interactive input detected; cannot prompt. Aborting publication.")
        return 1

    # Execute atomic publication
    print("\n[+] Publishing sanitized records to Neon PostgreSQL...")
    try:
        result = publish_to_neon(neon_url, clean_run, clean_evidence, clean_findings, clean_risks)
        print("[+] PUBLICATION SUCCESSFUL!")
        print(f"    - Assessment Run: {result['run']} inserted")
        print(f"    - Evidence Records: {result['evidence']} inserted")
        print(f"    - Findings: {result['findings']} inserted")
        print(f"    - Risk Snapshots: {result['risks']} inserted")
        print(f"[+] Assessment '{args.assessment_id}' is now live in Neon PostgreSQL.")
        return 0
    except Exception as exc:
        print(f"[-] ERROR during publication: {exc}")
        print("[-] Transaction rolled back completely. No records were modified.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

