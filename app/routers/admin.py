"""app/routers/admin.py — Administration (rôle ADMIN requis)."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.auth import Msg, UserOut
from app.security import require_admin

router = APIRouter(prefix="/api/v1/admin", tags=["🛡️ Admin"])
Admin  = Depends(require_admin())


@router.get("/stats", summary="Statistiques globales des utilisateurs")
async def get_stats(
    _: User = Admin,
    db: AsyncSession = Depends(get_db),
):
    return {
        "total":    await db.scalar(select(func.count(User.id))) or 0,
        "active":   await db.scalar(select(func.count(User.id)).where(User.is_active    == True)) or 0,
        "verified": await db.scalar(select(func.count(User.id)).where(User.is_verified  == True)) or 0,
        "with_2fa": await db.scalar(select(func.count(User.id)).where(User.totp_enabled == True)) or 0,
        "admins":   await db.scalar(select(func.count(User.id)).where(User.role == UserRole.ADMIN)) or 0,
    }

@router.get(
    "/users/{user_id}/login-history",
    summary="Historique des connexions avec adresse IP",
)
async def login_history(
    user_id: int,
    limit: int = Query(20, ge=1, le=100),
    _: User = Admin,
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import select, desc
    from app.models.user import User as UserModel
    
    # Vérifier que l'utilisateur existe
    user = await db.get(UserModel, user_id)
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    
    return {
        "user_id":        user.id,
        "email":          user.email,
        "last_login_at":  user.last_login_at,
        "last_login_ip":  getattr(user, "last_login_ip", None),
    }

@router.get("/users", summary="Lister les utilisateurs (paginé, recherche)")
async def list_users(
    page:   int           = Query(1, ge=1),
    size:   int           = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, description="Recherche email, username ou nom"),
    _: User = Admin,
    db: AsyncSession = Depends(get_db),
):
    q = select(User)
    if search:
        p = f"%{search}%"
        q = q.where(or_(
            User.email.ilike(p),
            User.username.ilike(p),
            User.full_name.ilike(p),
        ))

    total = await db.scalar(select(func.count()).select_from(q.subquery())) or 0
    q     = q.order_by(User.created_at.desc()).offset((page - 1) * size).limit(size)
    users = (await db.execute(q)).scalars().all()

    return {
        "total": total,
        "page":  page,
        "size":  size,
        "items": [UserOut.model_validate(u) for u in users],
    }


@router.get("/users/{user_id}", response_model=UserOut, summary="Détail d'un utilisateur")
async def get_user(
    user_id: int,
    _: User = Admin,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    return user


@router.patch("/users/{user_id}", response_model=UserOut, summary="Modifier un utilisateur")
async def update_user(
    user_id:     int,
    is_active:   Optional[bool]     = None,
    is_verified: Optional[bool]     = None,
    role:        Optional[UserRole] = None,
    current: User = Admin,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    if is_active is False and user.id == current.id:
        raise HTTPException(400, "Impossible de désactiver votre propre compte")
    if is_active   is not None: user.is_active   = is_active
    if is_verified is not None: user.is_verified = is_verified
    if role        is not None: user.role        = role
    await db.flush()
    return UserOut.model_validate(user)


@router.delete("/users/{user_id}", response_model=Msg, summary="Supprimer un utilisateur")
async def delete_user(
    user_id: int,
    current: User = Admin,
    db: AsyncSession = Depends(get_db),
):
    if user_id == current.id:
        raise HTTPException(400, "Impossible de supprimer votre propre compte")
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    await db.delete(user)
    return Msg(message=f"Utilisateur {user_id} supprimé")


@router.post(
    "/users/{user_id}/reset-2fa",
    response_model=Msg,
    summary="Réinitialiser la 2FA d'un utilisateur (support client)",
)
async def reset_2fa(
    user_id: int,
    _: User = Admin,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    user.totp_enabled = False
    user.totp_secret  = None
    user.backup_codes = None
    return Msg(message="2FA réinitialisée")
