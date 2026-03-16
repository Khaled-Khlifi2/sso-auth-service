"""app/models/user.py — Table users."""
import enum
import json
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, utcnow


class UserRole(str, enum.Enum):
    USER  = "user"
    ADMIN = "admin"



class User(Base):
    __tablename__ = "users"

    id:       Mapped[int]           = mapped_column(Integer, primary_key=True, index=True)
    email:    Mapped[str]           = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[Optional[str]] = mapped_column(String(100), unique=True, index=True)
    full_name:  Mapped[Optional[str]] = mapped_column(String(255))
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500))
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255))

    role: Mapped[UserRole] = mapped_column(
    SAEnum(
        UserRole,
        name="userrole",
        create_type=False,
        values_callable=lambda x: [e.value for e in x],
    ),
    default=UserRole.USER,
    nullable=False,
    )

    is_active:   Mapped[bool] = mapped_column(Boolean, default=True,  nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    totp_secret:  Mapped[Optional[str]] = mapped_column(String(64))
    totp_enabled: Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    backup_codes: Mapped[Optional[str]] = mapped_column(Text)
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(50))

    created_at:    Mapped[datetime]           = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_login_ip:      Mapped[Optional[str]] = mapped_column(String(50))
    

    def get_backup_codes(self) -> list[str]:
        return json.loads(self.backup_codes) if self.backup_codes else []

    def set_backup_codes(self, codes: list[str]) -> None:
        self.backup_codes = json.dumps(codes)

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN