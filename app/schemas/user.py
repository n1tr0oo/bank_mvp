import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import UserRole

# CWE-521 (Weakly Hashed/Weak Password Requirements):
# жёсткая политика пароля при регистрации.
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
_RE_LOWER = re.compile(r"[a-z]")
_RE_UPPER = re.compile(r"[A-Z]")
_RE_DIGIT = re.compile(r"\d")
_RE_SPECIAL = re.compile(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]")
_COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "qwerty", "qwerty123",
        "12345678", "123456789", "1234567890", "letmein", "welcome",
        "admin", "admin123", "iloveyou", "monkey", "dragon", "111111",
    }
)


def _validate_password_strength(value: str) -> str:
    if len(value) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(value) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters")
    if value.lower() in _COMMON_PASSWORDS:
        raise ValueError("Password is too common")
    classes = sum(
        bool(rx.search(value))
        for rx in (_RE_LOWER, _RE_UPPER, _RE_DIGIT, _RE_SPECIAL)
    )
    if classes < 3:
        raise ValueError(
            "Password must contain at least 3 of: lowercase, uppercase, digit, special"
        )
    return value


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    full_name: str = Field(min_length=2, max_length=255, strip_whitespace=True)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: UserRole
    created_at: datetime

    model_config = {"from_attributes": True}
