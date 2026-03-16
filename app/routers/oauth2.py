"""app/routers/oauth2.py — OAuth2 Google et GitHub."""
from fastapi import APIRouter, Depends, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.schemas.auth import TokenOut
from app.services import oauth_service as svc

router = APIRouter(prefix="/api/v1/oauth2", tags=["🌐 OAuth2"])


@router.get(
    "/providers",
    summary="Liste des providers OAuth2 configurés",
)
async def list_providers():
    """Retourne uniquement les providers avec des credentials configurés dans .env."""
    providers = []
    if settings.google_ok:
        providers.append({"name": "google", "display": "Google", "icon": "🔵"})
    if settings.github_ok:
        providers.append({"name": "github", "display": "GitHub", "icon": "⚫"})
    return {"providers": providers}


@router.get(
    "/login/{provider}",
    summary="Démarrer le flux OAuth2 (ouvrir dans le navigateur)",
)
async def oauth_login(
    provider: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Génère l'URL d'autorisation avec un state CSRF et redirige vers le provider.
    Ouvrir directement dans le navigateur :
    - http://localhost:8000/api/v1/oauth2/login/google
    - http://localhost:8000/api/v1/oauth2/login/github
    """
    redirect_url = await svc.build_redirect_url(provider, db)
    return RedirectResponse(redirect_url)


@router.get(
    "/callback/{provider}",
    response_model=TokenOut,
    summary="Callback OAuth2 (appelé automatiquement par le provider)",
)
async def oauth_callback(
    provider: str,
    code:     str = Query(..., description="Code d'autorisation reçu du provider"),
    state:    str = Query(..., description="State CSRF pour validation"),
    db: AsyncSession = Depends(get_db),
):
    """
    Le provider redirige ici après authentification.
    Valide le state CSRF, échange le code, crée ou connecte l'utilisateur.
    """
    return await svc.handle_callback(provider, code, state, db)
