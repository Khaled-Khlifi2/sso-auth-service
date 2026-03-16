"""app/routers/auth.py — Inscription, connexion, 2FA, refresh, logout."""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginIn, LoginOut, LogoutIn, Msg,
    RefreshIn, RegisterIn, TokenOut,
    TwoFAActivateOut, TwoFAConfirmIn, TwoFADisableIn,
    TwoFASetupOut, TwoFAVerifyLoginIn,
)
from app.security import (
    decode_access_token, get_client_ip, get_current_user, rate_limit,
)
from app.services import auth_service as svc

router  = APIRouter(prefix="/api/v1/auth", tags=["🔐 Auth"])
_bearer = HTTPBearer(auto_error=False)


@router.post(
    "/register",
    response_model=TokenOut,
    status_code=201,
    summary="Créer un compte",
)
async def register(
    body: RegisterIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    await rate_limit(f"reg:{get_client_ip(request)}", limit=5, window_sec=60)
    return await svc.register(body.email, body.username, body.password, body.full_name, db)


@router.post(
    "/login",
    response_model=LoginOut,
    summary="Se connecter (retourne les tokens ou requires_2fa=true)",
)
async def login(
    body: LoginIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    await rate_limit(f"login:{get_client_ip(request)}", limit=10, window_sec=60)
    return await svc.login(body.email, body.password, request, db)


@router.post(
    "/2fa/verify",
    response_model=TokenOut,
    summary="Login étape 2 — soumettre le code TOTP ou un code de secours",
)
async def verify_2fa_login(
    body: TwoFAVerifyLoginIn,
    db: AsyncSession = Depends(get_db),
):
    return await svc.verify_2fa_login(body.pending_token, body.code, db)


@router.get(
    "/2fa/setup",
    response_model=TwoFASetupOut,
    summary="Obtenir le secret TOTP et le QR code pour configurer l'application d'authentification",
)
async def setup_2fa(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    data = await svc.setup_2fa(user, db)
    return TwoFASetupOut(**data)


@router.post(
    "/2fa/verify-setup",
    response_model=TwoFAActivateOut,
    summary="Confirmer le premier code TOTP → activer la 2FA + recevoir les codes de secours",
)
async def confirm_2fa(
    body: TwoFAConfirmIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    data = await svc.confirm_2fa(user, body.code, db)
    return TwoFAActivateOut(**data)


@router.post(
    "/2fa/disable",
    response_model=Msg,
    summary="Désactiver la 2FA (mot de passe + code TOTP requis)",
)
async def disable_2fa(
    body: TwoFADisableIn,
    user: User = Depends(get_current_user),
):
    await svc.disable_2fa(user, body.password, body.code)
    return Msg(message="2FA désactivée avec succès")


@router.post(
    "/refresh",
    response_model=TokenOut,
    summary="Rafraîchir les tokens (rotation obligatoire du refresh token)",
)
async def refresh(
    body: RefreshIn,
    db: AsyncSession = Depends(get_db),
):
    return await svc.refresh_tokens(body.refresh_token, db)


@router.post(
    "/logout",
    response_model=Msg,
    summary="Se déconnecter — révoque les tokens",
)
async def logout(
    body: LogoutIn,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
):
    if creds:
        try:
            payload = await decode_access_token(creds.credentials)
            await svc.logout(payload, body.refresh_token, db)
        except Exception:
            pass   # token déjà expiré → logout quand même
    return Msg(message="Déconnexion réussie")
