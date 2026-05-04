import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.dependencies import get_client_ip, get_current_user, get_db, oauth2_scheme
from app.models.revoked_token import RevokedToken
from app.models.user import User, UserRole
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.user import UserCreate, UserResponse
from app.services.audit import write_audit_log
from app.services.security import create_access_token, decode_access_token, hash_password, verify_password

router = APIRouter()
logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)


def _safe_log_value(value: str | int | None) -> str:
    """CWE-117: запрет CRLF в значениях, попадающих в текстовый log."""
    if value is None:
        return "-"
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed",
        )

    # Роль зашита на сервере (CWE-915: Mass Assignment защита):
    # клиент не может указать роль через тело запроса — UserCreate её не содержит.
    user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=UserRole.client,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(
        "New user registered: id=%s role=%s",
        _safe_log_value(user.id),
        _safe_log_value(user.role.value),
    )
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()

    dummy_hash = "$2b$12$KIXSVi8SCfHIrXJ7q4rZNOjXB3Wt5.yCfwkfZDqEWH2tGPF2QlYy"
    password_ok = verify_password(
        login_data.password,
        user.hashed_password if user else dummy_hash,
    )

    if not user or not password_ok or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    write_audit_log(db, actor_id=user.id, action="LOGIN", ip_address=get_client_ip(request))

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Инвалидирует текущий JWT-токен, добавляя его jti в blacklist.

    Источник токена: Authorization-заголовок (API-клиенты) или session_token
    HttpOnly-cookie (UI). Если не указан ни один — current_user уже отбросит
    запрос как 401, поэтому ниже raw_token гарантированно не пуст.
    """
    raw_token = token or request.cookies.get("session_token")
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate credentials")
    payload = decode_access_token(raw_token)
    jti: str | None = payload.get("jti")
    exp_ts: float | None = payload.get("exp")
    if jti is None or exp_ts is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate credentials")
    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)

    # CWE-755: повторный logout того же токена не должен ронять сервис.
    try:
        db.add(RevokedToken(jti=jti, expires_at=expires_at))
        db.commit()
    except IntegrityError:
        db.rollback()  # уже отозван — нормально

    write_audit_log(
        db,
        actor_id=current_user.id,
        action="LOGOUT",
        ip_address=get_client_ip(request),
    )


@router.post("/token", response_model=TokenResponse, include_in_schema=False)
def token_oauth2(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """OAuth2-совместимый эндпоинт для Swagger UI (поле username = email)."""
    user = db.query(User).filter(User.email == form_data.username).first()

    dummy_hash = "$2b$12$KIXSVi8SCfHIrXJ7q4rZNOjXB3Wt5.yCfwkfZDqEWH2tGPF2QlYy"
    password_ok = verify_password(
        form_data.password,
        user.hashed_password if user else dummy_hash,
    )

    if not user or not password_ok or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    write_audit_log(db, actor_id=user.id, action="LOGIN", ip_address=get_client_ip(request))

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return {"access_token": token, "token_type": "bearer"}
