"""Initial schema — users, refresh_tokens, oauth_states

Revision ID: 0001
Revises:
Create Date: 2026-01-01 00:00:00
"""
import sqlalchemy as sa
from alembic import op

revision      = "0001"
down_revision = None
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id",              sa.Integer(),    nullable=False),
        sa.Column("email",           sa.String(255),  nullable=False),
        sa.Column("username",        sa.String(100),  nullable=True),
        sa.Column("full_name",       sa.String(255),  nullable=True),
        sa.Column("avatar_url",      sa.String(500),  nullable=True),
        sa.Column("hashed_password", sa.String(255),  nullable=True),
        sa.Column("role",
            sa.Enum("user", "admin", name="userrole"),
            nullable=False, server_default="user"),
        sa.Column("is_active",      sa.Boolean(),  nullable=False, server_default="true"),
        sa.Column("is_verified",    sa.Boolean(),  nullable=False, server_default="false"),
        sa.Column("totp_secret",    sa.String(64), nullable=True),
        sa.Column("totp_enabled",   sa.Boolean(),  nullable=False, server_default="false"),
        sa.Column("backup_codes",   sa.Text(),     nullable=True),
        sa.Column("oauth_provider", sa.String(50), nullable=True),
        sa.Column("created_at",     sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at",  sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email",    "users", ["email"],    unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "refresh_tokens",
        sa.Column("id",         sa.Integer(),   nullable=False),
        sa.Column("token",      sa.String(512), nullable=False),
        sa.Column("user_id",    sa.Integer(),   nullable=False),
        sa.Column("is_revoked", sa.Boolean(),   nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rt_token",   "refresh_tokens", ["token"],   unique=True)
    op.create_index("ix_rt_user_id", "refresh_tokens", ["user_id"], unique=False)

    op.create_table(
        "oauth_states",
        sa.Column("id",         sa.Integer(),   nullable=False),
        sa.Column("state",      sa.String(255), nullable=False),
        sa.Column("provider",   sa.String(50),  nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_oauth_state", "oauth_states", ["state"], unique=True)


def downgrade() -> None:
    op.drop_table("oauth_states")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
    op.execute("DROP TYPE IF EXISTS userrole")