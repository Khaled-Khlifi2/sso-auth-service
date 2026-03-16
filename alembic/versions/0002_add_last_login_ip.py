"""Add last_login_ip to users

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-16
"""
from alembic import op
import sqlalchemy as sa

revision      = "0002"
down_revision = "0001"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column("users",
        sa.Column("last_login_ip", sa.String(50), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("users", "last_login_ip")