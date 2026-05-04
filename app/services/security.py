"""
Криптография: bcrypt для паролей, JWT (HS256) для сессионных токенов.

Используется PyJWT 2.x вместо python-jose 3.x:
- python-jose тянет pyasn1<0.5.0, в котором есть CVE-2026-30922 (ASN.1 decoder).
  Pin python-jose не позволяет обновить pyasn1 без замены библиотеки.
- PyJWT не использует pyasn1 для HS256 (HMAC); зависимость отсутствует.
- API почти идентичен — заменили импорт и тип исключения.
"""
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from jwt import PyJWTError  # noqa: F401 — используется в dependencies.py
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode["exp"] = expire
    # jti (JWT ID) — уникальный идентификатор токена для blacklist
    to_encode["jti"] = str(uuid.uuid4())
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    # PyJWT по умолчанию проверяет exp; algorithms=[...] обязательно (CWE-347).
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
