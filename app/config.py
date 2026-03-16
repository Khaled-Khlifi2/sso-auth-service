"""app/config.py — Paramètres centralisés depuis .env"""
from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=True, extra="ignore"
    )

    APP_NAME:    str  = "SSO Auth"
    ENVIRONMENT: str  = "development"
    DEBUG:       bool = True
    BASE_URL:    str  = "http://localhost:8000"

    # Obligatoire — générer : python3 -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY: str

    JWT_ALGORITHM:               str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS:   int = 7

    # PostgreSQL local
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/sso_auth"

    # Redis — facultatif, fail-open si absent
    REDIS_URL: str = "redis://localhost:6379/0"

    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    MAX_LOGIN_ATTEMPTS:   int = 5
    LOCKOUT_DURATION_MIN: int = 15

    TOTP_ISSUER: str = "SSO Auth"

    FIRST_ADMIN_EMAIL:    str = ""
    FIRST_ADMIN_PASSWORD: str = ""

    GOOGLE_CLIENT_ID:     str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID:     str = ""
    GITHUB_CLIENT_SECRET: str = ""

    @field_validator("SECRET_KEY")
    @classmethod
    def key_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError(
                "SECRET_KEY doit faire ≥ 32 caractères. "
                "Générer : python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def google_ok(self) -> bool:
        return bool(self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_SECRET)

    @property
    def github_ok(self) -> bool:
        return bool(self.GITHUB_CLIENT_ID and self.GITHUB_CLIENT_SECRET)


settings = Settings()
