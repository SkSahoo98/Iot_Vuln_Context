"""Experiment query service using existing SQLAlchemy Experiment models."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.experiment import Experiment
from app.schemas.api import ExperimentDetailOut, ExperimentSummaryOut


def list_experiments(db: Session) -> list[ExperimentSummaryOut]:
    rows = db.scalars(
        select(Experiment).order_by(Experiment.created_at.desc())
    ).all()
    return [ExperimentSummaryOut.model_validate(row) for row in rows]


def get_experiment(db: Session, experiment_id: UUID) -> ExperimentDetailOut | None:
    row = db.scalar(
        select(Experiment)
        .where(Experiment.id == experiment_id)
        .options(selectinload(Experiment.results))
    )
    if row is None:
        return None
    return ExperimentDetailOut.model_validate(row)
