import logging
from typing import Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

logger = logging.getLogger("audit")


def _sanitize(value: Optional[str]) -> Optional[str]:
    """CWE-117: запрет CRLF-инъекции в текстовое логирование."""
    if value is None:
        return None
    return value.replace("\r", "\\r").replace("\n", "\\n")


def write_audit_log(
    db: Session,
    actor_id: int,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Контракт записи аудит-лога:
    - выполняется собственный commit (изолировано от бизнес-транзакции);
    - на ошибке БД — rollback и WARNING в текстовый лог, исключение НЕ пробрасывается
      (бизнес-операция уже завершена; CWE-755);
    - все строковые поля санитизируются от CRLF (CWE-117).
    """
    safe_action = _sanitize(action) or ""
    safe_target_type = _sanitize(target_type)
    safe_ip = _sanitize(ip_address)

    entry = AuditLog(
        actor_id=actor_id,
        action=safe_action,
        target_type=safe_target_type,
        target_id=target_id,
        ip_address=safe_ip,
    )
    try:
        db.add(entry)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.warning(
            "audit_write_failed | actor_id=%s | action=%s | target=%s:%s",
            actor_id,
            safe_action,
            safe_target_type,
            target_id,
        )
        return

    logger.info(
        "actor_id=%s | action=%s | target=%s:%s | ip=%s",
        actor_id,
        safe_action,
        safe_target_type,
        target_id,
        safe_ip,
    )
