"""app/security.py — JWT, bcrypt, rate limiting Redis, dépendances FastAPI."""
import secrets
import uuid
from datetime import timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db, utcnow

pwd    = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)


# ── Mots de passe ─────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd.verify(plain, hashed)


# ── JWT ───────────────────────────────────────────────────────
def create_access_token(user_id: int, email: str, role: str) -> str:
    """Crée un JWT HS256 signé avec JTI pour la blacklist."""
    return jwt.encode(
        {
            "sub":   str(user_id),
            "email": email,
            "role":  role,
            "jti":   str(uuid.uuid4()),   # identifiant unique pour la révocation
            "exp":   utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            "type":  "access",
        },
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token_value() -> str:
    return secrets.token_urlsafe(64)


async def decode_access_token(token: str) -> dict:
    """Décode le JWT et vérifie la blacklist Redis."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Mauvais type de token")

    jti = payload.get("jti")
    if jti:
        await _check_blacklist(jti)

    return payload


async def _check_blacklist(jti: str) -> None:
    """Vérifie si le JTI est dans la blacklist Redis. Fail-open si Redis absent."""
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2)
        exists = await r.exists(f"bl:{jti}")
        await r.aclose()
        if exists:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token révoqué")
    except HTTPException:
        raise
    except Exception:
        pass  # Redis absent → fail-open


async def blacklist_jti(jti: str, ttl_sec: int) -> None:
    """Ajoute un JTI à la blacklist Redis avec TTL = durée restante du token."""
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2)
        await r.setex(f"bl:{jti}", ttl_sec, "1")
        await r.aclose()
    except Exception:
        pass


# ── Dépendances FastAPI ───────────────────────────────────────
async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: AsyncSession = Depends(get_db),
):
    """Valide le Bearer token et retourne l'utilisateur connecté."""
    from app.models.user import User

    if not creds:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Token manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = await decode_access_token(creds.credentials)
    user    = await db.get(User, int(payload["sub"]))

    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte désactivé")

    return user


def require_admin():
    """Dependency factory — exige le rôle ADMIN."""
    from app.models.user import UserRole

    async def _check(user=Depends(get_current_user)):
        if user.role != UserRole.ADMIN:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès administrateur requis")
        return user

    return _check


# ── Rate limiting ─────────────────────────────────────────────
async def rate_limit(key: str, limit: int, window_sec: int) -> None:
    """Bloque si > limit requêtes dans window_sec secondes. Fail-open si Redis absent."""
    try:
        import redis.asyncio as aioredis
        r    = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=3)
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_sec)
        results = await pipe.execute()
        await r.aclose()
        if results[0] > limit:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Trop de requêtes — réessayez dans quelques instants",
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Redis absent → fail-open


# ── Verrouillage de compte ────────────────────────────────────
async def check_lockout(user_id: int) -> None:
    try:
        import redis.asyncio as aioredis
        r   = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=6)
        val = await r.get(f"lock:{user_id}")
        await r.aclose()
        if val and int(val) >= settings.MAX_LOGIN_ATTEMPTS:
            raise HTTPException(status.HTTP_423_LOCKED, "Compte temporairement verrouillé")
    except HTTPException:
        raise
    except Exception:
        pass


async def record_failed_login(user_id: int) -> None:
    try:
        import redis.asyncio as aioredis
        r    = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=5)
        pipe = r.pipeline()
        pipe.incr(f"lock:{user_id}")
        pipe.expire(f"lock:{user_id}", settings.LOCKOUT_DURATION_MIN * 60)
        await pipe.execute()
        await r.aclose()
    except Exception:
        pass


async def reset_failed_logins(user_id: int) -> None:
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2)
        await r.delete(f"lock:{user_id}")
        await r.aclose()
    except Exception:
        pass


# ── IP client ─────────────────────────────────────────────────
def get_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
