"""app/main.py — Application FastAPI."""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import engine
from app.models import User, UserRole, RefreshToken, OAuthState  # noqa: F401 — enregistre les modèles


# ── Démarrage / Arrêt ─────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Créer les tables si elles n'existent pas (idempotent)
    from app.database import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Créer le premier administrateur si configuré dans .env
    if settings.FIRST_ADMIN_EMAIL and settings.FIRST_ADMIN_PASSWORD:
        from sqlalchemy import select
        from app.database import AsyncSessionLocal
        from app.security import hash_password

        async with AsyncSessionLocal() as db:
            exists = await db.scalar(
                select(User).where(User.email == settings.FIRST_ADMIN_EMAIL)
            )
            if not exists:
                db.add(User(
                    email=settings.FIRST_ADMIN_EMAIL,
                    username="admin",
                    hashed_password=hash_password(settings.FIRST_ADMIN_PASSWORD),
                    role=UserRole.ADMIN,
                    is_active=True,
                    is_verified=True,
                ))
                await db.commit()
                print(f"✅  Admin créé : {settings.FIRST_ADMIN_EMAIL}")

    yield

    await engine.dispose()


# ── Application ───────────────────────────────────────────────
'''## SSO Auth Microservice

### Fonctionnalités
- **Auth locale** : inscription, connexion, refresh, logout
- **2FA TOTP** : Google Authenticator, Authy, codes de secours
- **OAuth2** : Google, GitHub (protection CSRF)
- **Rate limiting** + verrouillage de compte
- **JWT** avec blacklist Redis
- **RBAC** : user / admin'''
app = FastAPI(
    title=settings.APP_NAME,
    version="4.0.0",
    description="""

    """,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ───────────────────────────────────────────────────

from app.routers import auth, users, admin, oauth2  # noqa: E402

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(oauth2.router)


# ── Health check ──────────────────────────────────────────────

@app.get("/health", tags=["🏥 Health"], summary="État du service")
async def health():
    from sqlalchemy import text
    from app.database import AsyncSessionLocal

    result = {"status": "ok", "database": "ok", "redis": "ok"}

    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
    except Exception as e:
        result["database"] = f"error: {str(e)[:80]}"
        result["status"]   = "degraded"

    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, socket_timeout=2)
        await r.ping()
        await r.aclose()
    except Exception:
        result["redis"]  = "unavailable (fail-open actif)"
        result["status"] = "degraded"

    return result


# ── Gestionnaire d'erreurs global ─────────────────────────────

@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    import logging
    logging.getLogger("sso").exception(exc)
    if settings.DEBUG:
        return JSONResponse(status_code=500, content={"detail": str(exc)})
    return JSONResponse(status_code=500, content={"detail": "Erreur interne du serveur"})
