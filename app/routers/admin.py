import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from sqlalchemy.orm import Session

from app.dependencies import get_client_ip, get_db, require_role
from app.models.revoked_token import RevokedToken
from app.models.user import User, UserRole
from app.schemas.user import UserResponse
from app.services.audit import write_audit_log

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/users", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/users/{user_id}/deactivate", response_model=UserResponse)
def deactivate_user(
    request: Request,
    user_id: int = Path(ge=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    if user_id == current_user.id:
        # Защита от самоблокировки администратора (CWE-269: improper privilege management).
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin cannot deactivate themselves",
        )
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    user.is_active = False
    db.commit()
    db.refresh(user)

    write_audit_log(
        db,
        actor_id=current_user.id,
        action="DEACTIVATE_USER",
        target_type="user",
        target_id=user.id,
        ip_address=get_client_ip(request),
    )
    return user


@router.post("/revoked-tokens/cleanup", status_code=status.HTTP_200_OK)
def cleanup_revoked_tokens(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """
    Защита от CWE-400: периодическая чистка таблицы revoked_tokens.
    Удаляет записи, у которых exp уже истёк — токен в любом случае
    не пройдёт верификацию JWT, поэтому хранить его в blacklist бессмысленно.
    """
    now = datetime.now(timezone.utc)
    deleted = (
        db.query(RevokedToken)
        .filter(RevokedToken.expires_at < now)
        .delete(synchronize_session=False)
    )
    db.commit()

    write_audit_log(
        db,
        actor_id=current_user.id,
        action="CLEANUP_REVOKED_TOKENS",
        target_type="revoked_token",
        ip_address=get_client_ip(request),
    )
    return {"deleted": int(deleted)}
