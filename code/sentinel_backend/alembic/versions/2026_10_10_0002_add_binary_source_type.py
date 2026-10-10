"""Allow direct ELF/PE upload tasks.

Revision ID: b600cba20a02
Revises: 8d2f2b30a041
"""
from collections.abc import Sequence

from alembic import op

revision: str = "b600cba20a02"
down_revision: str | None = "8d2f2b30a041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE source_type_enum ADD VALUE IF NOT EXISTS 'BINARY'")


def downgrade() -> None:
    # PostgreSQL enum values cannot be safely removed in place.
    pass
