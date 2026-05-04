from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# CSP по умолчанию: максимально строгий (для JSON-API).
_CSP_STRICT = "default-src 'none'; frame-ancestors 'none'"

# CSP для собственного UI (Jinja2-страницы + локальные CSS/JS):
# никаких внешних доменов, никаких inline-скриптов.
# Inline-стили запрещены — все стили вынесены в /static/styles.css.
_CSP_UI = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)

# CSP для Swagger UI / ReDoc: они грузят JS/CSS/шрифты с jsdelivr CDN
# и используют inline-скрипты для конфигурации страницы.
_CSP_DOCS = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)

_DOCS_PATHS = ("/docs", "/redoc", "/docs/oauth2-redirect")
_UI_PATHS = ("/", "/ui", "/static")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Защита от CWE-693 (Protection Mechanism Failure).
    Добавляет к каждому ответу набор security-headers (HSTS, CSP,
    X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).
    Для путей Swagger UI / ReDoc CSP смягчён, чтобы UI мог загрузить ассеты с CDN.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        path = request.url.path
        is_docs = any(path == p or path.startswith(p + "/") for p in _DOCS_PATHS)
        is_ui = (
            path == "/"
            or path.startswith("/ui/")
            or path.startswith("/static/")
        )
        if is_docs:
            csp = _CSP_DOCS
        elif is_ui:
            csp = _CSP_UI
        else:
            csp = _CSP_STRICT

        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        # same-origin: внутри сайта Referer виден (нужен для CSRF-проверки в UI),
        # на внешних переходах Referer не отправляется (защита приватности).
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        response.headers.setdefault("Cache-Control", "no-store")
        return response
