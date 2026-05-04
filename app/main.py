import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import Base, engine
from app.dependencies import get_current_user_optional
from app.middleware.body_size import MaxBodySizeMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.models import audit_log, credit_application, revoked_token, user  # noqa: F401 — side-effect imports for SQLAlchemy table registration
from app.routers import admin, applications, audit, auth, ui
from app.routers.auth import limiter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Bank Credit MVP",
    description="Variant 1 — Credit application service",
    version="1.0.0",
    # /docs и /redoc открыты только если ENABLE_DOCS=true (по умолчанию — в dev).
    # В production: ENABLE_DOCS=false → оба URL возвращают 404.
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.MAX_BODY_BYTES)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(applications.router, prefix="/applications", tags=["Applications"])
app.include_router(audit.router, prefix="/audit-logs", tags=["Audit"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])
# UI-роутер не имеет префикса: обслуживает / и /ui/*.
app.include_router(ui.router, tags=["UI"], include_in_schema=False)


def _is_ui_path(path: str) -> bool:
    return path == "/" or path.startswith("/ui/")


# Один общий Templates instance для error-страниц (UI использует свой в ui.py).
_error_templates = Jinja2Templates(directory="app/templates")


# Понятные сообщения для частых HTTP-кодов на UI.
_ERROR_PRESETS: dict[int, dict[str, str]] = {
    400: {
        "title": "Некорректный запрос",
        "description": "Сервер не смог обработать форму. Проверьте введённые данные.",
    },
    403: {
        "title": "Доступ запрещён",
        "description": "У вашей роли нет прав на эту страницу или действие.",
    },
    404: {
        "title": "Страница не найдена",
        "description": "Запрошенный объект не существует, либо у вас нет к нему доступа.",
    },
    409: {
        "title": "Конфликт состояния",
        "description": "Действие невозможно: объект уже находится в состоянии, "
                       "не позволяющем выполнение операции (например, заявка уже рассмотрена).",
    },
    413: {
        "title": "Запрос слишком большой",
        "description": "Размер тела запроса превышает допустимый лимит.",
    },
    422: {
        "title": "Не удалось обработать данные",
        "description": "Форма содержит некорректные значения. Вернитесь и проверьте поля.",
    },
    429: {
        "title": "Слишком много запросов",
        "description": "Подождите минуту и попробуйте снова — сработала защита от перебора.",
    },
    500: {
        "title": "Внутренняя ошибка сервера",
        "description": "Что-то пошло не так. Если повторится — сообщите администратору.",
    },
}


def _render_ui_error(
    request: Request,
    code: int,
    detail: str | None = None,
) -> "Jinja2Templates.TemplateResponse":
    """Рендер красивой страницы ошибки для UI-путей."""
    preset = _ERROR_PRESETS.get(code, {
        "title": f"Ошибка {code}",
        "description": "Произошла непредвиденная ошибка.",
    })
    # Пробуем подгрузить пользователя для рендера шапки (без 401).
    try:
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            user = get_current_user_optional(request, db)
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        user = None

    referer = request.headers.get("referer")
    back_url = "/ui/applications" if user else "/ui/login"
    if referer and referer != str(request.url):
        back_url = referer

    return _error_templates.TemplateResponse(
        request,
        "error.html",
        {
            "current_user": user,
            "code": code,
            "title": preset["title"],
            "description": preset["description"],
            "detail": detail,
            "back_url": back_url,
            "back_label": "Назад",
        },
        status_code=code,
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    CWE-209: единая точка для HTTPException.
    Для UI:
      401 → редирект на /ui/login (нужен логин);
      остальное → красивая страница ошибки.
    Для API → JSON.
    """
    if _is_ui_path(request.url.path):
        if exc.status_code == 401:
            return RedirectResponse(url="/ui/login", status_code=303)
        return _render_ui_error(request, exc.status_code, str(exc.detail) if exc.detail else None)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Pydantic-валидация: на UI красивая 422-страница, в API — детали ошибок."""
    if _is_ui_path(request.url.path):
        # Берём первую ошибку валидации как краткую подсказку.
        first = exc.errors()[0] if exc.errors() else None
        detail = (
            f"{'.'.join(str(x) for x in first['loc'])}: {first['msg']}"
            if first else None
        )
        return _render_ui_error(request, 422, detail)
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    CWE-209/CWE-754/CWE-755: единый обработчик неперехваченных исключений.
    Никаких внутренних подробностей наружу.
    """
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    if _is_ui_path(request.url.path):
        return _render_ui_error(request, 500)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.api_route("/health", methods=["GET", "HEAD"], tags=["Health"])
def health():
    """Health-check для Docker, Render и uptime-мониторов.

    Поддерживает HEAD (UptimeRobot/Pingdom используют его по умолчанию)
    и GET (для curl/браузера/Docker healthcheck).
    """
    return {"status": "ok"}
