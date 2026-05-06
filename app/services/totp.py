"""
TOTP-сервис (RFC 6238) для двухфакторной аутентификации.

Используется библиотека pyotp:
- 6-значный код, шаг 30 секунд, алгоритм HMAC-SHA1 (стандарт совместимости с
  Google Authenticator, Authy, Microsoft Authenticator, 1Password и др.).
- При проверке допускается окно ±1 шаг (30 сек до/после) для компенсации
  расхождения часов клиента и сервера.

QR-код для первичной настройки рендерится в data:image/png;base64,... — это
позволяет показать его прямо в HTML без сохранения файла. CSP `img-src 'self' data:`
уже разрешает такие ссылки.
"""
import base64
import io

import pyotp
import qrcode
from qrcode.image.pil import PilImage

ISSUER_NAME = "Bank Credit MVP"


def generate_secret() -> str:
    """Генерирует новый base32-секрет для TOTP (160 бит = 32 base32-символа)."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_name: str) -> str:
    """
    Возвращает otpauth:// URI для сканирования QR-кодом.
    account_name — обычно email пользователя.
    """
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=ISSUER_NAME)


def qr_data_url(uri: str) -> str:
    """
    Кодирует QR-код в data URL (base64 PNG).
    Используется в шаблоне как <img src="data:image/png;base64,...">.
    """
    img: PilImage = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify(secret: str, code: str) -> bool:
    """
    Проверяет 6-значный TOTP-код.
    valid_window=1 → допускаем коды на ±1 шаг (30 сек) от текущего.
    Защита от replay не реализована — для усиления стоит запоминать
    последний использованный код и отвергать его повторное применение.
    """
    if not code or not secret:
        return False
    code = code.replace(" ", "").strip()
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)
