"""app/schemas/auth.py — Schémas Pydantic pour toutes les requêtes et réponses."""
import re
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, field_validator, model_validator

from app.models.user import UserRole


def _validate_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Minimum 8 caractères")
    if not re.search(r"[A-Za-z]", v):
        raise ValueError("Au moins une lettre")
    if not re.search(r"\d", v):
        raise ValueError("Au moins un chiffre")
    return v


# ── Requêtes Auth ─────────────────────────────────────────────

class RegisterIn(BaseModel):
    email:     EmailStr
    username:  str
    full_name: Optional[str] = None
    password:  str

    @field_validator("password")
    @classmethod
    def pw_strong(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("username")
    @classmethod
    def un_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("3 caractères minimum")
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Lettres, chiffres, - et _ uniquement")
        return v.lower()

    model_config = {
        "json_schema_extra": {
            "example": {
                "email":     "alice@example.com",
                "username":  "alice",
                "full_name": "Alice Martin",
                "password":  "SecurePass1",
            }
        }
    }


class LoginIn(BaseModel):
    email:    EmailStr
    password: str

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "SecurePass1"}
        }
    }


class RefreshIn(BaseModel):
    refresh_token: str


class LogoutIn(BaseModel):
    refresh_token: Optional[str] = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password:     str

    @field_validator("new_password")
    @classmethod
    def pw_strong(cls, v: str) -> str:
        return _validate_password(v)

    @model_validator(mode="after")
    def must_differ(self) -> "ChangePasswordIn":
        if self.current_password == self.new_password:
            raise ValueError("Le nouveau mot de passe doit être différent")
        return self


class UpdateProfileIn(BaseModel):
    full_name:  Optional[str] = None
    username:   Optional[str] = None
    avatar_url: Optional[str] = None


# ── Requêtes 2FA ──────────────────────────────────────────────

class TwoFAVerifyLoginIn(BaseModel):
    """Étape 2 du login quand 2FA est activée."""
    pending_token: str
    code:          str   # code TOTP 6 chiffres OU code de secours XXXX-XXXX

    model_config = {
        "json_schema_extra": {
            "example": {"pending_token": "abc123...", "code": "123456"}
        }
    }


class TwoFAConfirmIn(BaseModel):
    """Premier code TOTP pour activer la 2FA."""
    code: str

    model_config = {"json_schema_extra": {"example": {"code": "123456"}}}


class TwoFADisableIn(BaseModel):
    """Désactiver la 2FA — nécessite mot de passe + code TOTP actuel."""
    password: str
    code:     str


# ── Réponses ──────────────────────────────────────────────────

class UserOut(BaseModel):
    id:             int
    email:          str
    username:       Optional[str]
    full_name:      Optional[str]
    avatar_url:     Optional[str]
    role:           UserRole
    is_active:      bool
    is_verified:    bool
    totp_enabled:   bool
    oauth_provider: Optional[str]
    created_at:     datetime
    last_login_at:  Optional[datetime] = None
    last_login_ip:      Optional[str] = None
    last_login_country: Optional[str] = None
    last_login_city:    Optional[str] = None
    last_login_isp:     Optional[str] = None

    model_config = {"from_attributes": True}


class TokenOut(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int   # secondes
    user:          UserOut


class LoginOut(BaseModel):
    """
    Retourné par POST /auth/login.
    - Sans 2FA : access_token + refresh_token + user
    - Avec 2FA : requires_2fa=true + pending_token (pas de tokens JWT encore)
    """
    access_token:  Optional[str]     = None
    refresh_token: Optional[str]     = None
    token_type:    str               = "bearer"
    expires_in:    Optional[int]     = None
    user:          Optional[UserOut] = None
    requires_2fa:  bool              = False
    pending_token: Optional[str]     = None


class TwoFASetupOut(BaseModel):
    """Retourné par GET /auth/2fa/setup."""
    secret:           str   # secret base32 à entrer manuellement
    qr_uri:           str   # otpauth:// URI
    qr_image_base64:  str   # PNG base64 — afficher dans <img src="data:image/png;base64,...">


class TwoFAActivateOut(BaseModel):
    """Retourné par POST /auth/2fa/verify-setup."""
    message:      str
    backup_codes: List[str]   # afficher UNE SEULE FOIS


class Msg(BaseModel):
    message: str

class LoginHistoryOut(BaseModel):
    id:          int
    ip_address:  Optional[str]
    user_agent:  Optional[str]
    provider:    str
    success:     bool
    fail_reason: Optional[str]
    created_at:  datetime
    model_config = {"from_attributes": True}
