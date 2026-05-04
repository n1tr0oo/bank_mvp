import csv
import io
from datetime import datetime
from typing import Iterable, Optional

# Allowlist полей экспорта аудит-лога (CWE-200, CWE-915):
# наружу попадают ТОЛЬКО эти атрибуты, новые поля модели не утекают автоматически.
AUDIT_EXPORT_FIELDS: tuple[str, ...] = (
    "id",
    "actor_id",
    "action",
    "target_type",
    "target_id",
    "ip_address",
    "created_at",
)

# Префиксы, с которых Excel/LibreOffice/Numbers начинают вычисление формулы
# (CWE-1236: Improper Neutralization of Formula Elements in a CSV File).
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n")


def _escape_csv_cell(value: object) -> str:
    """
    Возвращает безопасное строковое представление значения для CSV.
    Если значение начинается с символа-триггера формулы — добавляет апостроф
    в начало (стандартная защита от CSV Formula Injection).
    """
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    s = str(value)
    if s and s[0] in _FORMULA_TRIGGERS:
        return "'" + s
    return s


def stream_audit_csv(
    rows: Iterable[object],
    fields: tuple[str, ...] = AUDIT_EXPORT_FIELDS,
    chunk_size: int = 200,
) -> Iterable[bytes]:
    """
    Потоковая (streaming) сериализация аудит-лога в CSV.
    Не загружает весь набор результатов в память — строки выдаются батчами
    (CWE-770: защита от неограниченного выделения памяти при экспорте).
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(fields)

    def _drain() -> bytes:
        data = buffer.getvalue().encode("utf-8")
        buffer.seek(0)
        buffer.truncate(0)
        return data

    yield _drain()

    count = 0
    for row in rows:
        cells = [_escape_csv_cell(getattr(row, f, None)) for f in fields]
        writer.writerow(cells)
        count += 1
        if count % chunk_size == 0:
            yield _drain()

    tail = _drain()
    if tail:
        yield tail


def safe_export_filename(prefix: str, ext: str = "csv") -> str:
    """
    Безопасное имя файла для Content-Disposition (CWE-22 / CWE-73).
    Никаких пользовательских частей: только префикс + UTC timestamp + расширение.
    Имя НЕ используется как путь в файловой системе — только в заголовке ответа.
    """
    allowed_prefix = "".join(c for c in prefix if c.isalnum() or c in ("_", "-"))
    if not allowed_prefix:
        allowed_prefix = "export"
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    allowed_ext = "".join(c for c in ext if c.isalnum())
    return f"{allowed_prefix}_{ts}.{allowed_ext}"


def parse_optional_datetime(value: Optional[str]) -> Optional[datetime]:
    """
    Жёсткий parser для query-параметра ?since=...
    Принимает только ISO 8601 (YYYY-MM-DDTHH:MM:SS[+ZZ:ZZ]).
    Любая другая строка → ValueError на уровне FastAPI/Pydantic.
    """
    if value is None or value == "":
        return None
    return datetime.fromisoformat(value)
