from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    # В production установить ENABLE_DOCS=false для скрытия /docs и /redoc
    ENABLE_DOCS: bool = True
    # Лимит размера тела HTTP-запроса (CWE-770). 1 МБ по умолчанию.
    MAX_BODY_BYTES: int = 1 * 1024 * 1024
    # Доверенные заголовки X-Forwarded-For: список IP/CIDR прокси (CWE-348).
    # Пусто = не доверяем заголовкам, берём request.client.host.
    TRUSTED_PROXIES: str = ""

    model_config = {"env_file": ".env"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
