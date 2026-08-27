"""add not-reproduced verification verdict

Revision ID: 8d2f2b30a041
Revises: c2343e8e8bb0
"""
from collections.abc import Sequence

from alembic import op

revision: str = "8d2f2b30a041"
down_revision: str | None = "c2343e8e8bb0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
    DO $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
            WHERE t.typname = 'verify_status_enum' AND e.enumlabel = 'NOT_REPRODUCED'
        ) THEN
            ALTER TYPE verify_status_enum ADD VALUE 'NOT_REPRODUCED';
        END IF;
    END $$;
    """)


def downgrade() -> None:
    # PostgreSQL enum values cannot be removed safely without rebuilding every
    # dependent column. Keeping the unused value is the non-destructive rollback.
    pass
