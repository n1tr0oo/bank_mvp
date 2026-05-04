from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models.revoked_token import RevokedToken
from app.models.user import User, UserRole
from app.services.security import decode_access_token

# auto_error=False: позволяет UI получать токен из cookie, а не только заголовка.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)

# Имя cookie для UI-сессии. HttpOnly + SameSite=Lax + Secure (в production).
SESSION_COOKIE_NAME = "session_token"


def get_db():
    """
    Контракт жизненного цикла сессии БД (CWE-404 / CWE-460):
    - на исключении — rollback незавершённой транзакции;
    - в любом случае — close (возврат соединения в пул).
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _trusted_proxies() -> set[str]:
    raw = (settings.TRUSTED_PROXIES or "").strip()
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


def get_client_ip(request: Request) -> str | None:
    """
    Защита от CWE-348 (Use of Less Trusted Source).
    X-Forwarded-For принимаем ТОЛЬКО если непосредственный peer находится
    в списке доверенных прокси (TRUSTED_PROXIES). Иначе берём request.client.host
    и игнорируем заголовок — клиент мог его подделать.
    """
    peer = request.client.host if request.client else None
    trusted = _trusted_proxies()
    if peer and peer in trusted:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Берём первый IP из цепочки — это исходный клиент.
            return forwarded.split(",")[0].strip()
    return peer


def _extract_token(request: Request, header_token: Optional[str]) -> Optional[str]:
    """
    Источник токена для аутентификации:
    1) Authorization: Bearer ... (для API-клиентов и Swagger UI);
    2) HttpOnly-cookie SESSION_COOKIE_NAME (для собственного UI).
    Cookie ставится только сервером при login через UI-роутер.
    """
    if header_token:
        return header_token
    return request.cookies.get(SESSION_COOKIE_NAME)


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    raw_token = _extract_token(request, token)
    if not raw_token:
        raise credentials_exception
    try:
        payload = decode_access_token(raw_token)
        user_id_raw = payload.get("sub")
        jti_raw = payload.get("jti")
        if not isinstance(user_id_raw, str) or not isinstance(jti_raw, str):
            raise credentials_exception
        user_id: str = user_id_raw
        jti: str = jti_raw
    except PyJWTError as exc:
        raise credentials_exception from exc

    # Проверяем blacklist — отозванный токен отклоняется немедленно
    revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    if revoked:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id), User.is_active.is_(True)).first()
    if user is None:
        raise credentials_exception
    return user


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Для UI: возвращает пользователя при валидной cookie-сессии,
    либо None — без выбрасывания 401. Используется на публичных страницах
    (login/register), чтобы перенаправлять уже залогиненных.
    """
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        return None
    try:
        payload = decode_access_token(raw_token)
        user_id_raw = payload.get("sub")
        jti_raw = payload.get("jti")
        if not isinstance(user_id_raw, str) or not isinstance(jti_raw, str):
            return None
    except PyJWTError:
        return None

    if db.query(RevokedToken).filter(RevokedToken.jti == jti_raw).first():
        return None
    return db.query(User).filter(User.id == int(user_id_raw), User.is_active.is_(True)).first()


def require_role(*roles: UserRole) -> Callable:
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return checker


def require_application_access(application, current_user: User) -> None:
    """
    Объектная авторизация (CWE-639, CWE-285):
    - admin — видит всё;
    - manager — видит все заявки (бизнес-роль решает);
    - client — только свои.
    Бросает 404 (а не 403), чтобы не подтверждать существование чужого ресурса.
    """
    if current_user.role in (UserRole.admin, UserRole.manager):
        return
    if current_user.role == UserRole.client and application.client_id == current_user.id:
        return
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
