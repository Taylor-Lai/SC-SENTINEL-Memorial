"""bootstrap the complete SENTINEL schema

Revision ID: 4ef7c9b5a210
Revises:

This baseline is deliberately idempotent. Early SENTINEL deployments used
``Base.metadata.create_all`` without an Alembic version table; running this
migration against those databases must adopt the existing schema without
destroying data, while a fresh database must receive the complete schema.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "4ef7c9b5a210"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    import app.models  # noqa: F401 -- register every ORM model
    from app.core.database import Base

    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    # A baseline downgrade must never drop an adopted production schema.
    pass
