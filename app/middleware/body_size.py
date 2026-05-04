from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """
    Защита от CWE-770 (Allocation of Resources Without Limits).
    Отвергает запросы с телом больше max_bytes — как по Content-Length,
    так и при потоковом чтении (chunked transfer без Content-Length).
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400, content={"detail": "Invalid Content-Length"}
                )
            if length > self.max_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )

        # Защита от chunked transfer без Content-Length:
        # перехватываем receive() и считаем байты на лету.
        body_size = 0
        max_bytes = self.max_bytes
        original_receive = request.receive

        async def limited_receive():
            nonlocal body_size
            message = await original_receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"") or b""
                body_size += len(chunk)
                if body_size > max_bytes:
                    return {"type": "http.disconnect"}
            return message

        request._receive = limited_receive  # type: ignore[attr-defined]
        return await call_next(request)
