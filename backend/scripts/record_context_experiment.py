"""
Record the IoT context-aware risk experiment in PostgreSQL.

Uses the project's SQLAlchemy session and Experiment models.
Safe to run repeatedly: upserts by experiment_name + model_version.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
for path in (BACKEND_ROOT, PROJECT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.experiment import Experiment, ExperimentResult

EXPERIMENT_NAME = "IoT Context-Aware Dynamic Risk Scoring Experiment"
MODEL_VERSION = "IoT-RISK-v1"
DATASET_VERSION = "context-experiment-v1"

OBJECTIVE = (
    "Evaluate whether IoT-specific contextual factors can change the risk "
    "score of the same vulnerability while keeping the vulnerability and "
    "base severity constant."
)

HYPOTHESIS = (
    "The same vulnerability will produce different dynamic risk scores "
    "when IoT-specific contextual conditions change."
)

METHODOLOGY = (
    "The MQTT_WITHOUT_TLS vulnerability with HIGH base severity was "
    "evaluated under two IoT contexts. Scenario A represents a lower "
    "criticality sensor context, while Scenario B represents a highly "
    "critical and more exposed IoT context. The IoT-RISK-v1 deterministic "
    "scoring model was applied to both scenarios."
)

PARAMETERS = {
    "vulnerability": "MQTT_WITHOUT_TLS",
    "base_severity": "HIGH",
    "risk_model": MODEL_VERSION,
    "base_severity_weight": 0.50,
    "context_weight": 0.50,
    "scenario_a": {
        "name": "Sensor Context",
        "device_criticality": 0.3,
        "network_exposure": 0.3,
        "anonymous_access": True,
        "tls_enabled": False,
        "firmware_security": 0.5,
        "risk_score": 67.5,
        "risk_level": "HIGH",
    },
    "scenario_b": {
        "name": "Critical Context",
        "device_criticality": 1.0,
        "network_exposure": 0.9,
        "anonymous_access": True,
        "tls_enabled": False,
        "firmware_security": 0.2,
        "risk_score": 82.5,
        "risk_level": "CRITICAL",
    },
}

CONCLUSION = (
    "The experiment demonstrates that, under the proposed deterministic "
    "scoring model, the same vulnerability and base severity can produce "
    "different risk scores when IoT-specific contextual factors change. "
    "The observed risk-score difference between the two contexts was 15.0 points."
)

METRICS = [
    (
        "sensor_context_risk_score",
        Decimal("67.5"),
        "Scenario A: lower-criticality sensor context",
    ),
    (
        "critical_context_risk_score",
        Decimal("82.5"),
        "Scenario B: highly critical and exposed IoT context",
    ),
    (
        "risk_score_difference",
        Decimal("15.0"),
        "Difference between Scenario B and Scenario A",
    ),
]


def main() -> int:
    session = SessionLocal()
    try:
        existing = session.scalar(
            select(Experiment).where(
                Experiment.experiment_name == EXPERIMENT_NAME,
                Experiment.model_version == MODEL_VERSION,
            )
        )

        now = datetime.now(UTC)

        if existing:
            experiment = existing
            experiment.objective = OBJECTIVE
            experiment.hypothesis = HYPOTHESIS
            experiment.methodology = METHODOLOGY
            experiment.dataset_version = DATASET_VERSION
            experiment.parameters = PARAMETERS
            experiment.status = "COMPLETED"
            experiment.conclusion = CONCLUSION
            experiment.end_date = now
            # Replace results to keep metrics idempotent.
            experiment.results.clear()
            action = "updated"
        else:
            experiment = Experiment(
                experiment_name=EXPERIMENT_NAME,
                objective=OBJECTIVE,
                hypothesis=HYPOTHESIS,
                methodology=METHODOLOGY,
                dataset_version=DATASET_VERSION,
                model_version=MODEL_VERSION,
                parameters=PARAMETERS,
                start_date=now,
                end_date=now,
                status="COMPLETED",
                conclusion=CONCLUSION,
            )
            session.add(experiment)
            action = "created"

        session.flush()

        for metric_name, metric_value, notes in METRICS:
            session.add(
                ExperimentResult(
                    experiment_id=experiment.id,
                    metric_name=metric_name,
                    metric_value=metric_value,
                    model_name=MODEL_VERSION,
                    notes=notes,
                )
            )

        session.commit()

        print(f"\nExperiment {action} successfully!")
        print("--------------------------------")
        print(f"Experiment ID : {experiment.id}")
        print(f"Experiment    : {EXPERIMENT_NAME}")
        print(f"Model         : {MODEL_VERSION}")
        print("Status        : COMPLETED")
        print()
        print("Results:")
        print("  Sensor Context   : 67.5 HIGH")
        print("  Critical Context : 82.5 CRITICAL")
        print("  Difference       : 15.0")
        print()
        return 0
    except Exception as exc:
        session.rollback()
        print(f"Failed to record experiment: {exc}")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
