import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import Base, engine
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


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    CWE-209: единая точка для HTTPException.
    Для UI-путей при 401 — редиректим на /ui/login (вместо JSON-ошибки),
    для остального — стандартный JSON.
    """
    if _is_ui_path(request.url.path) and exc.status_code == 401:
        return RedirectResponse(url="/ui/login", status_code=303)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Скрываем подробности валидации Pydantic от внешних клиентов на UI.
    if _is_ui_path(request.url.path):
        return RedirectResponse(url="/ui/login", status_code=303)
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    CWE-209/CWE-754/CWE-755: единый обработчик неперехваченных исключений.
    Никаких подробностей об ошибке наружу.
    """
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    if _is_ui_path(request.url.path):
        return RedirectResponse(url="/ui/login", status_code=303)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}
