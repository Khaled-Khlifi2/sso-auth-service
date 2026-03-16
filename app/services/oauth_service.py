"""app/services/oauth_service.py — OAuth2 Google et GitHub."""
import secrets
from datetime import timedelta
from typing import Optional

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import utcnow
from app.models.oauth import OAuthState
from app.models.token import RefreshToken
from app.models.user import User, UserRole
from app.schemas.auth import TokenOut, UserOut
from app.security import create_access_token, create_refresh_token_value

# ── Configuration des providers ───────────────────────────────
PROVIDERS: dict = {
    "google": {
        "auth_url":     "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url":    "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        "scopes":       "openid email profile",
    },
    "github": {
        "auth_url":     "https://github.com/login/oauth/authorize",
        "token_url":    "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scopes":       "read:user user:email",
    },
}


def _get_client_creds(provider: str) -> tuple[str, str]:
    """Retourne (client_id, client_secret) selon le provider."""
    if provider == "google":
        if not settings.google_ok:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Google OAuth2 non configuré — remplir GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET dans .env",
            )
        return settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET

    if provider == "github":
        if not settings.github_ok:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "GitHub OAuth2 non configuré — remplir GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET dans .env",
            )
        return settings.GITHUB_CLIENT_ID, settings.GITHUB_CLIENT_SECRET

    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Provider '{provider}' non supporté")


def _redirect_uri(provider: str) -> str:
    return f"{settings.BASE_URL}/api/v1/oauth2/callback/{provider}"


# ── Génération de l'URL de redirection ───────────────────────

async def build_redirect_url(provider: str, db: AsyncSession) -> str:
    """
    Crée un state CSRF, le stocke en base, retourne l'URL du provider.
    Le state expire en 10 minutes.
    """
    cfg      = PROVIDERS.get(provider)
    if not cfg:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Provider '{provider}' non supporté")

    cid, _   = _get_client_creds(provider)
    state    = secrets.token_urlsafe(32)

    db.add(OAuthState(
        state=state,
        provider=provider,
        expires_at=utcnow() + timedelta(minutes=10),
    ))

    params = {
        "client_id":     cid,
        "redirect_uri":  _redirect_uri(provider),
        "response_type": "code",
        "scope":         cfg["scopes"],
        "state":         state,
    }
    if provider == "google":
        params["access_type"] = "offline"

    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{cfg['auth_url']}?{query}"


# ── Traitement du callback ────────────────────────────────────

async def handle_callback(
    provider: str, code: str, state: str, db: AsyncSession
) -> TokenOut:
    """
    1. Valide le state CSRF
    2. Échange le code contre un access token
    3. Récupère les infos utilisateur
    4. Crée ou retrouve l'utilisateur en base
    5. Émet les tokens JWT
    """
    cfg = PROVIDERS.get(provider)
    if not cfg:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Provider '{provider}' non supporté")

    # Valider le state CSRF
    state_row = await db.scalar(
        select(OAuthState).where(
            OAuthState.state    == state,
            OAuthState.provider == provider,
        )
    )
    if not state_row:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "State OAuth2 invalide — possible attaque CSRF")
    if state_row.expires_at < utcnow():
        await db.delete(state_row)
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "State OAuth2 expiré — recommencez la connexion")
    await db.delete(state_row)

    # Échanger le code contre un access token provider
    cid, csecret = _get_client_creds(provider)
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(
            cfg["token_url"],
            headers={"Accept": "application/json"},
            data={
                "client_id":     cid,
                "client_secret": csecret,
                "code":          code,
                "grant_type":    "authorization_code",
                "redirect_uri":  _redirect_uri(provider),
            },
        )
        token_data = resp.json()

    if "error" in token_data:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Erreur OAuth2 : {token_data.get('error_description', token_data['error'])}",
        )

    provider_access_token = token_data["access_token"]

    # Récupérer les infos utilisateur
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            cfg["userinfo_url"],
            headers={
                "Authorization": f"Bearer {provider_access_token}",
                "Accept":        "application/json",
            },
        )
        user_info = resp.json()

    email, name, avatar = _parse_user_info(provider, user_info)

    # GitHub ne retourne pas toujours l'email public — requête complémentaire
    if provider == "github" and not email:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {provider_access_token}",
                    "Accept":        "application/json",
                },
            )
            emails = resp.json()
        primary = next((e for e in emails if e.get("primary") and e.get("email")), None)
        email   = primary["email"] if primary else None

    if not email:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Impossible de récupérer l'email depuis le provider OAuth2",
        )

    # Trouver ou créer l'utilisateur
    user = await db.scalar(select(User).where(User.email == email))

    if not user:
        username = await _unique_username(email.split("@")[0], db)
        user = User(
            email=email,
            username=username,
            full_name=name,
            avatar_url=avatar,
            oauth_provider=provider,
            role=UserRole.USER,
            is_active=True,
            is_verified=True,    # email validé par le provider
        )
        db.add(user)
        await db.flush()
    elif not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

    user.last_login_at = utcnow()
    if avatar and not user.avatar_url:
        user.avatar_url = avatar

    # Émettre les tokens JWT
    access_token  = create_access_token(user.id, user.email, user.role.value)
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


# ── Helpers privés ────────────────────────────────────────────

def _parse_user_info(provider: str, info: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Normalise les infos utilisateur selon le provider."""
    if provider == "google":
        return info.get("email"), info.get("name"), info.get("picture")
    if provider == "github":
        return (
            info.get("email") or "",
            info.get("name") or info.get("login"),
            info.get("avatar_url"),
        )
    return None, None, None


async def _unique_username(base: str, db: AsyncSession) -> str:
    """Génère un username unique en ajoutant un suffixe si nécessaire."""
    clean = "".join(c for c in base.lower() if c.isalnum() or c in "-_")[:20] or "user"
    for i in range(100):
        candidate = clean if i == 0 else f"{clean}{i}"
        if not await db.scalar(select(User).where(User.username == candidate)):
            return candidate
    return clean + secrets.token_hex(3)
