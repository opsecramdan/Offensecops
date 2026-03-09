from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone

from app.db.session import get_db
from app.db.models import User, AuditLog
from app.api.deps import get_current_user, require_roles
from app.core.security import hash_password

router = APIRouter()

VALID_ROLES = ["admin", "manager", "pentester", "viewer", "auditor"]


# ── Schemas ──────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: str = "pentester"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class PasswordReset(BaseModel):
    new_password: str


def user_to_dict(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "failed_login_attempts": u.failed_login_attempts or 0,
        "locked_until": u.locked_until.isoformat() if u.locked_until else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


async def log_action(db: AsyncSession, actor: User, action: str, resource_id: str = None):
    log = AuditLog(
        user_id=actor.id,
        username=actor.username,
        action=action,
        resource_type="user",
        resource_id=resource_id,
        response_code=200,
    )
    db.add(log)


# ── Routes ───────────────────────────────────────────────────
@router.get("/")
async def list_users(
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "manager")),
):
    query = select(User)
    if search:
        from sqlalchemy import or_
        query = query.where(or_(
            User.username.ilike(f"%{search}%"),
            User.email.ilike(f"%{search}%"),
            User.full_name.ilike(f"%{search}%"),
        ))
    if role:
        query = query.where(User.role == role)
    if is_active is not None:
        query = query.where(User.is_active == is_active)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    query = query.order_by(User.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()

    return {"total": total, "items": [user_to_dict(u) for u in users]}


@router.post("/", status_code=201)
async def create_user(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    if data.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Valid: {VALID_ROLES}")

    # Check duplicate username/email
    existing = await db.execute(
        select(User).where((User.username == data.username) | (User.email == data.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Password minimal 8 karakter")

    user = User(
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        hashed_password=hash_password(data.password),
        role=data.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await log_action(db, current_user, f"create_user:{data.username}", user.id)
    await db.commit()
    await db.refresh(user)
    return user_to_dict(user)


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return user_to_dict(current_user)


@router.patch("/me/password")
async def change_my_password(
    data: PasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.core.security import verify_password
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Password lama tidak benar")
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password baru minimal 8 karakter")

    current_user.hashed_password = hash_password(data.new_password)
    await log_action(db, current_user, "change_password", current_user.id)
    await db.commit()
    return {"message": "Password berhasil diubah"}


@router.get("/{user_id}")
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "manager")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user_to_dict(user)


@router.patch("/{user_id}")
async def update_user(
    user_id: str,
    data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Cegah admin ubah role dirinya sendiri
    if str(user.id) == str(current_user.id) and data.role and data.role != user.role:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    if data.role and data.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role")

    for field, val in data.model_dump(exclude_none=True).items():
        setattr(user, field, val)

    await log_action(db, current_user, f"update_user:{user.username}", user_id)
    await db.commit()
    await db.refresh(user)
    return user_to_dict(user)


@router.post("/{user_id}/reset-password")
async def reset_password(
    user_id: str,
    data: PasswordReset,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password minimal 8 karakter")

    user.hashed_password = hash_password(data.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    await log_action(db, current_user, f"reset_password:{user.username}", user_id)
    await db.commit()
    return {"message": f"Password for {user.username} reset successfully"}


@router.post("/{user_id}/toggle-active")
async def toggle_active(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user.id) == str(current_user.id):
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    user.is_active = not user.is_active
    action = "activate_user" if user.is_active else "deactivate_user"
    await log_action(db, current_user, f"{action}:{user.username}", user_id)
    await db.commit()
    return {"message": f"User {'activated' if user.is_active else 'deactivated'}", "is_active": user.is_active}


@router.post("/{user_id}/unlock")
async def unlock_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.locked_until = None
    user.failed_login_attempts = 0
    await log_action(db, current_user, f"unlock_user:{user.username}", user_id)
    await db.commit()
    return {"message": f"User {user.username} unlocked"}


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    if str(user_id) == str(current_user.id):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await log_action(db, current_user, f"delete_user:{user.username}", user_id)
    await db.delete(user)
    await db.commit()
