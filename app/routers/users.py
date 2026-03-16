"""app/routers/users.py — Profil utilisateur."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import ChangePasswordIn, Msg, UpdateProfileIn, UserOut
from app.security import get_current_user, hash_password, verify_password

router = APIRouter(prefix="/api/v1/users", tags=["👤 Profil"])


@router.get(
    "/me",
    response_model=UserOut,
    summary="Mon profil",
)
async def get_profile(user: User = Depends(get_current_user)):
    return user


@router.patch(
    "/me",
    response_model=UserOut,
    summary="Modifier mon profil (full_name, username, avatar_url)",
)
async def update_profile(
    body: UpdateProfileIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.username is not None:
        conflict = await db.scalar(
            select(User).where(User.username == body.username, User.id != user.id)
        )
        if conflict:
            raise HTTPException(409, "Username déjà utilisé")
        user.username = body.username

    if body.full_name  is not None: user.full_name  = body.full_name
    if body.avatar_url is not None: user.avatar_url = body.avatar_url

    await db.flush()
    await db.refresh(user)
    return user


@router.post(
    "/me/change-password",
    response_model=Msg,
    summary="Changer le mot de passe (vérifie le mot de passe actuel)",
)
async def change_password(
    body: ChangePasswordIn,
    user: User = Depends(get_current_user),
):
    if not user.hashed_password:
        raise HTTPException(400, "Compte OAuth2 — aucun mot de passe local")
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(401, "Mot de passe actuel incorrect")

    user.hashed_password = hash_password(body.new_password)
    return Msg(message="Mot de passe modifié avec succès")
