"""app/models/oauth.py — Table oauth_states (protection CSRF)."""
from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, utcnow


class OAuthState(Base):
    """
    State token CSRF pour les flux OAuth2.
    Créé avant la redirection vers le provider, validé au callback.
    TTL : 10 minutes.
    """
    __tablename__ = "oauth_states"

    id:         Mapped[int] = mapped_column(Integer, primary_key=True)
    state:      Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    provider:   Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
