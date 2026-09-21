"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-31 17:45:00.000000
"""

from typing import Sequence, Union

from alembic import op

from app.models import Base

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all tables from the approved SQLAlchemy metadata."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    """Drop all application tables. Development use only."""
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
