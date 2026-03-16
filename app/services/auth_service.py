"""app/services/auth_service.py — Toute la logique d'authentification."""
import secrets
from datetime import timedelta
from typing import Optional

from app.security import get_client_ip

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import utcnow
from app.models.token import RefreshToken
from app.models.user import User, UserRole
from app.schemas.auth import LoginOut, TokenOut, UserOut
from app.security import (
    blacklist_jti,
    check_lockout,
    create_access_token,
    create_refresh_token_value,
    get_client_ip,
    hash_password,
    record_failed_login,
    reset_failed_logins,
    verify_password,
)
from app.totp_utils import (
    generate_backup_codes,
    new_totp_secret,
    totp_provisioning_uri,
    totp_qr_base64,
    verify_backup_code,
    verify_totp_code,
)

# Stockage en mémoire des pending tokens 2FA (TTL 5 min)
# Suffit pour un seul serveur — utiliser Redis pour un déploiement multi-instance
_pending_2fa: dict[str, dict] = {}


def _clean_expired_pending() -> None:
    now = utcnow()
    for k in [k for k, v in _pending_2fa.items() if v["exp"] < now]:
        del _pending_2fa[k]


async def _emit_tokens(user: User, db: AsyncSession) -> TokenOut:
    """Émet un access token JWT + un refresh token en base."""
    
    role = user.role.value if hasattr(user.role, 'value') else user.role
    access_token = create_access_token(user.id, user.email, role)
    refresh_value = create_refresh_token_value()

    db.add(RefreshToken(
        token=refresh_value,
        user_id=user.id,
        expires_at=utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    ))

    return TokenOut(
        access_token=access_token,
        refresh_token=refresh_value,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserOut.model_validate(user),
    )


# ── Inscription ───────────────────────────────────────────────

async def register(
    email: str, username: str, password: str,
    full_name: Optional[str], db: AsyncSession,
) -> TokenOut:
    if await db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email déjà utilisé")
    if await db.scalar(select(User).where(User.username == username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Username déjà pris")

    user = User(
        email=email,
        username=username,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=UserRole.USER,
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    await db.flush()
    return await _emit_tokens(user, db)


# ── Connexion ─────────────────────────────────────────────────

async def login(
    email: str, password: str, request: Request, db: AsyncSession
) -> LoginOut:
    user = await db.scalar(select(User).where(User.email == email))

    if not user or not user.hashed_password:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email ou mot de passe incorrect")

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

    await check_lockout(user.id)

    if not verify_password(password, user.hashed_password):
        await record_failed_login(user.id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email ou mot de passe incorrect")

    await reset_failed_logins(user.id)
    user.last_login_at = utcnow()
    from app.security import get_client_ip
    user.last_login_ip = get_client_ip(request)

    # 2FA activée → retourner un pending_token au lieu des vrais tokens
    if user.totp_enabled:
        _clean_expired_pending()
        pt = secrets.token_urlsafe(32)
        _pending_2fa[pt] = {
            "user_id": user.id,
            "exp":     utcnow() + timedelta(minutes=5),
        }
        return LoginOut(requires_2fa=True, pending_token=pt)

    tokens = await _emit_tokens(user, db)
    return LoginOut(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        user=tokens.user,
    )


# ── Login étape 2 (2FA) ───────────────────────────────────────

async def verify_2fa_login(
    pending_token: str, code: str, db: AsyncSession
) -> TokenOut:
    _clean_expired_pending()
    entry = _pending_2fa.get(pending_token)

    if not entry or entry["exp"] < utcnow():
        _pending_2fa.pop(pending_token, None)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Token 2FA expiré ou invalide")

    user = await db.get(User, entry["user_id"])
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

    # Tenter TOTP puis backup code
    valid = verify_totp_code(user.totp_secret or "", code)
    if not valid and user.backup_codes:
        ok, updated_json = verify_backup_code(code, user.backup_codes)
        if ok:
            user.backup_codes = updated_json
            valid = True

    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code 2FA invalide")

    del _pending_2fa[pending_token]
    user.last_login_at = utcnow()
    return await _emit_tokens(user, db)


# ── Setup 2FA ─────────────────────────────────────────────────

async def setup_2fa(user: User, db: AsyncSession) -> dict:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La 2FA est déjà activée")

    secret = new_totp_secret()
    user.totp_secret  = secret
    user.totp_enabled = False   # pas encore activée — confirmée au prochain appel
    await db.flush()

    return {
        "secret":          secret,
        "qr_uri":          totp_provisioning_uri(secret, user.email),
        "qr_image_base64": totp_qr_base64(secret, user.email),
    }


async def confirm_2fa(user: User, code: str, db: AsyncSession) -> dict:
    if not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Appelez d'abord GET /api/v1/auth/2fa/setup")

    if not verify_totp_code(user.totp_secret, code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code TOTP invalide")

    plain, hashed = generate_backup_codes()
    user.totp_enabled = True
    user.set_backup_codes(hashed)
    await db.flush()

    return {"message": "2FA activée avec succès", "backup_codes": plain}


async def disable_2fa(user: User, password: str, code: str) -> None:
    if not verify_password(password, user.hashed_password or ""):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Mot de passe incorrect")
    if not verify_totp_code(user.totp_secret or "", code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code TOTP invalide")

    user.totp_enabled = False
    user.totp_secret  = None
    user.backup_codes = None


# ── Refresh / Logout ──────────────────────────────────────────

async def refresh_tokens(refresh_token_value: str, db: AsyncSession) -> TokenOut:
    row = await db.scalar(
        select(RefreshToken).where(RefreshToken.token == refresh_token_value)
    )
    if not row or row.is_revoked or row.expires_at < utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token invalide ou expiré")

    user = await db.get(User, row.user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

    row.is_revoked = True   # rotation obligatoire
    return await _emit_tokens(user, db)


async def logout(
    payload: dict,
    refresh_token_value: Optional[str],
    db: AsyncSession,
) -> None:
    # Blacklister le JTI dans Redis
    jti = payload.get("jti")
    exp = payload.get("exp")
    if jti and exp:
        ttl = max(0, int(exp) - int(utcnow().timestamp()))
        if ttl > 0:
            await blacklist_jti(jti, ttl)

    # Révoquer le refresh token en base
    if refresh_token_value:
        row = await db.scalar(
            select(RefreshToken).where(RefreshToken.token == refresh_token_value)
        )
        if row:
            row.is_revoked = True
