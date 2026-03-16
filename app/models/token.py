"""app/models/token.py — Table refresh_tokens."""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, utcnow


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id:         Mapped[int]  = mapped_column(Integer, primary_key=True)
    token:      Mapped[str]  = mapped_column(String(512), unique=True, index=True, nullable=False)
    user_id:    Mapped[int]  = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
